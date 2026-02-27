import fs from 'node:fs';
import crypto from 'node:crypto';
import readline from 'node:readline';

import crc32 from 'crc-32';
import { filesize } from 'filesize';

/**
 * Utility helper functions for TeraBox API requests
 * @module helper
 */

/**
 * Calculate proper chunk size for upload process
 * @param {integer} fileSize - File size in bytes
 * @param {Boolean} is_vip - VIP user flag
 * @returns {integer} Calculated chunk size
 */
function getChunkSize(fileSize, is_vip = true) {
    const MiB = 1024 * 1024;
    const GiB = 1024 * MiB;
    
    const limitSizes = [4, 8, 16, 32, 64, 128];
    
    if(!is_vip){
        return limitSizes.at(0) * MiB;
    }
    
    for (const limit of limitSizes) {
        if (fileSize <= limit * GiB) {
            return limit * MiB;
        }
    }
    
    return limitSizes.at(-1) * MiB;
}

/**
 * Calculate hashes for specific local file
 * @param {string} filePath - Path to local file
 * @returns {Object} Calculated hashes for specific local file
 */
async function hashFile(filePath) {
    const stat = fs.statSync(filePath);
    const sliceSize = 256 * 1024;
    const splitSize = getChunkSize(stat.size);
    const hashedData = newProgressData();
    
    let crcHash = 0;
    const fileHash = crypto.createHash('md5');
    const sliceHash = crypto.createHash('md5');
    let chunkHash = crypto.createHash('md5');
    
    const hashData = {
        crc32: 0,
        slice: '',
        file: '',
        etag: '',
        chunks: []
    };
    
    let bytesRead = 0;
    let allBytesRead = 0;
    
    const stream = fs.createReadStream(filePath);
    
    try {
        for await (const data of stream) {
            fileHash.update(data);
            
            crcHash = crc32.buf(data, crcHash);
            
            let offset = 0;
            while (offset < data.length) {
                const remaining = data.length - offset;
                
                const sliceRemaining = sliceSize - allBytesRead;
                const chunkRemaining = splitSize - bytesRead;
                
                const sliceAllowed = allBytesRead < sliceSize;
                const readLimit = sliceAllowed
                    ? Math.min(remaining, chunkRemaining, sliceRemaining)
                    : Math.min(remaining, chunkRemaining);
                
                const chunk = data.subarray(offset, offset + readLimit);
                chunkHash.update(chunk);
                
                if (sliceAllowed) {
                    sliceHash.update(chunk);
                }
                
                offset += readLimit;
                allBytesRead += readLimit;
                bytesRead += readLimit;
                
                if (bytesRead >= splitSize) {
                    hashData.chunks.push(chunkHash.digest('hex'));
                    chunkHash = crypto.createHash('md5');
                    bytesRead = 0;
                }
            }
            
            hashedData.all = hashedData.parts[0] = allBytesRead;
            printProgressLog('Hashing', hashedData, stat.size);
        }
        
        if (bytesRead > 0) {
            hashData.chunks.push(chunkHash.digest('hex'));
        }
        
        hashData.crc32 = crcHash >>> 0;
        hashData.slice = sliceHash.digest('hex');
        hashData.file = fileHash.digest('hex');
        hashData.etag = hashData.file;
        
        if(hashData.chunks.length > 1){
            const chunksJSON = JSON.stringify(hashData.chunks);
            const chunksEtag = crypto.createHash('md5').update(chunksJSON).digest('hex');
            hashData.etag = `${chunksEtag}-${hashData.chunks.length}`;
        }
        
        console.log();
        return hashData;
    }
    catch (error) {
        console.log();
        throw error;
    }
}

async function runWithConcurrencyLimit(data, tasks, limit) {
    let index = 0;
    let failed = false;
    
    const runTask = async () => {
        while (index < tasks.length && !failed) {
            const currentIndex = index++;
            await tasks[currentIndex]();
        }
    };
    
    const workers = Array.from({ length: limit }, () => runTask());
    
    try{
        await Promise.all(workers);
    }
    catch(error){
        console.error('\n[ERROR]', unwrapErrorMessage(error));
        failed = true;
    }
    
    return {ok: !failed, data: data};
};

/**
 * Format seconds to "99h99m99s" string
 * @param {string} remTimeInt - remaining time in seconds
 * @returns {Object} return "99h99m99s" string
 */
function formatEta(remTimeInt){
    if (!Number.isFinite(remTimeInt) || remTimeInt < 0) return '---------';
    const remTimeSec = remTimeInt > 99*3636+35 ? 99*3636+35 : remTimeInt;
    
    const remSec = Math.floor(remTimeSec % 60);
    const remMin = Math.floor((remTimeSec % 3600) / 60);
    const remHrs = Math.floor(remTimeSec / 3600);
    const [remH, remM, remS] = [remHrs, remMin, remSec].map(t => String(t).padStart(2, '0'));
    const remTimeStr = `${remH}h${remM}m${remS}s`;
    return remTimeStr;
}

function printProgressLog(prepText, sentData, fsize){
    readline.cursorTo(process.stdout, 0, null);
    
    const uploadedBytesSum = Object.values(sentData.parts).reduce((acc, value) => acc + value, 0);
    const uploadedBytesStr = filesize(uploadedBytesSum, {standard: 'iec', round: 3, pad: true, separator: '.'});
    const filesizeBytesStr = filesize(fsize, {standard: 'iec', round: 3, pad: true});
    const uploadedBytesFStr = `(${uploadedBytesStr}/${filesizeBytesStr})`;
    
    const uploadSpeed = sentData.all * 1000 / (Date.now() - sentData.start) || 0;
    const uploadSpeedStr = filesize(uploadSpeed, {standard: 'si', round: 2, pad: true, separator: '.'}) + '/s';
    
    const remainingTimeInt = Math.max((fsize - uploadedBytesSum) / uploadSpeed, 0);
    const remainingTimeStr = formatEta(remainingTimeInt) + ' left...';
    
    const percentage = Math.floor((uploadedBytesSum / fsize) * 100);
    const percentageFStr = `${percentage}% ${uploadedBytesFStr}`;
    const uploadStatusArr = [percentageFStr, uploadSpeedStr, remainingTimeStr];
    process.stdout.write(`${prepText}: ${uploadStatusArr.join(', ')}`);
    readline.clearLine(process.stdout, 1);
}

function md5MismatchText(hash1, hash2, partnum, total){
    return [
        `MD5 hash mismatch for file (part: ${partnum} of ${total})`,
        `[Actual MD5:${hash1} / Got MD5:${hash2}]`,
    ];
}

async function uploadChunkTask(app, data, file, partSeq, uploadData, externalAbort) {
    const splitSize = getChunkSize(data.size);
    const start = partSeq * splitSize;
    const end = Math.min(start + splitSize, data.size) - 1;
    const maxTries = uploadData.maxTries;
    
    const uploadLog = (chunkSize) => {
        uploadData.all += chunkSize;
        uploadData.parts[partSeq] += chunkSize;
        printProgressLog('Uploading', uploadData, data.size);
    };
    
    const blob_size = end + 1 - start;
    const buffer = Buffer.alloc(blob_size);
    await file.read(buffer, 0, blob_size, start);
    const blob = new Blob([buffer], { type: 'application/octet-stream' });
    let is_ok = false;
    
    for (let i = 0; i < maxTries; i++) {
        if (externalAbort.aborted) {
            break;
        }
        
        try{
            const res = await app.uploadChunk(data, partSeq, blob, null, externalAbort);
            const chunkMd5 = data.hash.chunks[partSeq];
            
            // check if we have chunks hash
            if (app.CheckMd5Val(chunkMd5) && res.md5 !== chunkMd5){
                const md5Err = md5MismatchText(chunkMd5, res.md5, partSeq+1, data.hash.chunks.length);
                throw new Error(md5Err.join('\n\t'));
            }
            
            // check if we don't have chunk hash and data.hash_check not set to false
            const skipChunkHashCheck = typeof data.hash_check === 'boolean' && data.hash_check === false;
            if(!app.CheckMd5Val(chunkMd5) && !skipChunkHashCheck){
                const calcChunkMd5 = crypto.createHash('md5').update(buffer).digest('hex');
                if(calcChunkMd5 !== res.md5){
                    const md5Err = md5MismatchText(calcChunkMd5, res.md5, partSeq+1, data.hash.chunks.length);
                    throw new Error(md5Err.join('\n\t'));
                }
            }
            
            // update chunkMd5 to res.md5
            if(app.CheckMd5Val(res.md5) && chunkMd5 !== res.md5){
                data.hash.chunks[partSeq] = res.md5;
            }
            
            // log uploaded
            data.uploaded[partSeq] = true;
            uploadLog(blob_size);
            is_ok = true;
            
            break;
        }
        catch(error){
            if (externalAbort.aborted) {
                break;
            }
            
            readline.clearLine(process.stdout, 0);
            readline.cursorTo(process.stdout, 0, null);
            
            let message = error.message;
            if(error.cause){
                message += ' Cause';
                if(error.cause.errno){
                    message += ' #' + error.cause.errno;
                }
                if(error.cause.code){
                    message += ' ' + error.cause.code;
                }
            }
            
            const uplFailedMsg1 = ' -> Upload failed for part #' + (partSeq+1);
            const uplFailedMsg2 = `: ${message}`;
            const doRetry = i+1 != maxTries ? `, retry #${i+1}` : '';
            
            process.stdout.write(uplFailedMsg1 + uplFailedMsg2 + doRetry + '...\n');
            uploadLog(0);
        }
    }
    
    if(!is_ok){
        throw new Error(`Upload failed! [PART #${partSeq+1}]`);
    }
}

function newProgressData() {
    return {
        all: 0,
        start: Date.now(),
        parts: {},
    };
}

/**
 * Helper function for uploading chunks to TeraBox
 * @param {TeraBoxApp} app - File size in bytes
 * @param {Object} data - Upload data parameters
 * @param {integer} maxTasks - maximum task for uploading
 * @param {integer} maxTries - maximum tries for chunk uploading
 * @returns {Object} Upload data parameters and status
 */
async function uploadChunks(app, data, filePath, maxTasks = 10, maxTries = 5) {
    const splitSize = getChunkSize(data.size);
    const totalChunks = data.hash.chunks.length;
    const lastChunkSize = data.size - splitSize * (data.hash.chunks.length - 1);
    
    const tasks = [];
    const uploadData = newProgressData();
    const externalAbortController = new AbortController();
    uploadData.maxTries = maxTries;
    
    if(data.uploaded.filter(pStatus => pStatus == false).length > 0){
        for (let partSeq = 0; partSeq < totalChunks; partSeq++) {
            uploadData.parts[partSeq] = 0;
            if(data.uploaded[partSeq]){
                const chunkSize = partSeq < totalChunks - 1 ? splitSize : lastChunkSize;
                uploadData.parts[partSeq] = chunkSize;
            }
        }
        
        const file = await fs.promises.open(filePath, 'r');
        for (let partSeq = 0; partSeq < totalChunks; partSeq++) {
            if(!data.uploaded[partSeq]){
                tasks.push(() => {
                    return uploadChunkTask(app, data, file, partSeq, uploadData, externalAbortController.signal);
                });
            }
        }
        
        printProgressLog('Uploading', uploadData, data.size);
        const cMaxTasks = totalChunks > maxTasks ? maxTasks : totalChunks;
        const upload_status = await runWithConcurrencyLimit(data, tasks, cMaxTasks);
        
        console.log();
        externalAbortController.abort();
        await file.close();
        
        return upload_status;
    }
    
    return {ok: true, data};
}

/**
 * Helper function unwraping Error Message
 * @param {Object} err - Error object
 * @returns {Object} Error data
 */
function unwrapErrorMessage(err) {
    if (!err) {
        return;
    }
    
    let e = err;
    let res = err.message;
    while (e.cause) {
        e = e.cause;
        if (e.message) {
            res += ': ' + e.message;
        }
    }
    
    return res;
}

export {
    getChunkSize,
    hashFile,
    formatEta,
    uploadChunks,
    unwrapErrorMessage,
};
