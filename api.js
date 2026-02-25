import { FormData, Client, buildConnector, request } from 'undici';
import { CookieJar } from 'tough-cookie';

import crypto from 'node:crypto';
import tls from 'node:tls';

/**
 * Main module for api interacting with TeraBox
 * @module api
 */

/**
 * Constructs a remote file path by combining a directory and filename, ensuring proper slash formatting
 * @param {string} sdir - The directory path (with or without trailing slash)
 * @param {string} sfile - The filename to append to the directory path
 * @returns {string} The combined full path with exactly one slash between directory and filename
 * @example
 * makeRemoteFPath('documents', 'file.txt')    // returns 'documents/file.txt'
 * makeRemoteFPath('documents/', 'file.txt')   // returns 'documents/file.txt'
 * @ignore
 */
function makeRemoteFPath(sdir, sfile){
    const tdir = sdir.match(/\/$/) ? sdir : sdir + '/';
    return tdir + sfile;
}

/**
 * A utility class for handling application/x-www-form-urlencoded data
 * Wraps URLSearchParams with additional convenience methods and encoding behavior
 * @class
 */
class FormUrlEncoded {
    /**
     * Creates a new FormUrlEncoded instance
     * @param {Object.<string, string>} [params] - Optional initial parameters as key-value pairs
     * @example
     * const form = new FormUrlEncoded({ foo: 'bar', baz: 'qux' });
     */
    constructor(params) {
        this.data = new URLSearchParams();
        if(typeof params === 'object' && params !== null){
            for (const [key, value] of Object.entries(params)) {
                this.data.append(key, value);
            }
        }
    }
    /**
     * Sets or replaces a parameter value
     * @param {string} param - The parameter name
     * @param {string} value - The parameter value
     * @returns {void}
     */
    set(param, value){
        this.data.set(param, value);
    }
    /**
     * Appends a new value to an existing parameter
     * @param {string} param - The parameter name
     * @param {string} value - The parameter value
     * @returns {void}
     */
    append(param, value){
        this.data.append(param, value);
    }
    /**
     * Removes a parameter
     * @param {string} param - The parameter name to remove
     * @returns {void}
     */
    delete(param){
        this.data.delete(param);
    }
    /**
     * Returns the encoded string representation (space encoded as %20)
     * Suitable for application/x-www-form-urlencoded content
     * @returns {string} The encoded form data
     * @example
     * form.str(); // returns "foo=bar&baz=qux"
     */
    str(){
        return this.data.toString().replace(/\+/g, '%20');
    }
    /**
     * Returns the underlying URLSearchParams object
     * @returns {URLSearchParams} The native URLSearchParams instance
     */
    url(){
        return this.data;
    }
}

/**
 * Generates a signed download token using a modified RC4-like algorithm
 *
 * This function implements a stream cipher similar to RC4 that:
 * <br>1. Initializes a permutation array using the secret key (s1)
 * <br>2. Generates a pseudorandom keystream
 * <br>3. XORs the input data (s2) with the keystream
 * <br>4. Returns the result as a Base64-encoded string
 *
 * @param {string} s1 - The secret key used for signing (should be at least 1 character)
 * @param {string} s2 - The input data to be signed
 * @returns {string} Base64-encoded signature
 * @example
 * const signature = signDownload('secret-key', 'data-to-sign');
 * // Returns something like: "X3p8YFJjUA=="
 */
function signDownload(s1, s2) {
    // Initialize permutation array (p) and key array (a)
    const p = new Uint8Array(256);
    const a = new Uint8Array(256);
    const result = [];
    
    // Key-scheduling algorithm (KSA)
    // Initialize the permutation array with the secret key
    Array.from({ length: 256 }, (_, i) => {
        a[i] = s1.charCodeAt(i % s1.length);
        p[i] = i;
    });
    
    // Scramble the permutation array using the key
    let j = 0;
    Array.from({ length: 256 }, (_, i) => {
        j = (j + p[i] + a[i]) % 256;
        [p[i], p[j]] = [p[j], p[i]]; // swap
    });
    
    // Pseudo-random generation algorithm (PRGA)
    // Generate keystream and XOR with input data
    let i = 0; j = 0;
    Array.from({ length: s2.length }, (_, q) => {
        i = (i + 1) % 256;
        j = (j + p[i]) % 256;
        [p[i], p[j]] = [p[j], p[i]]; // swap
        const k = p[(p[i] + p[j]) % 256];
        result.push(s2.charCodeAt(q) ^ k);
    });
    
    // Return the result as Base64
    return Buffer.from(result).toString('base64');
}

/**
 * Validates whether a string is a properly formatted MD5 hash
 * <br>
 * <br>Checks if the input:
 * <br>1. Is exactly 32 characters long
 * <br>2. Contains only hexadecimal characters (a-f, 0-9)
 * <br>3. Is in lowercase
 * <br>
 * <br>Note: This only validates the format, not the cryptographic correctness of the hash.
 *
 * @param {*} md5 - The value to check (typically a string)
 * @returns {boolean} True if the input is a valid MD5 format, false otherwise
 * @example
 * checkMd5val('d41d8cd98f00b204e9800998ecf8427e') // returns true
 * checkMd5val('D41D8CD98F00B204E9800998ECF8427E') // returns false (uppercase)
 * checkMd5val('z41d8cd98f00b204e9800998ecf8427e') // returns false (invalid character)
 * checkMd5val('d41d8cd98f')                       // returns false (too short)
 */
function checkMd5val(md5){
    if(typeof md5 !== 'string') return false;
    return /^[a-f0-9]{32}$/.test(md5);
}

/**
 * Validates that all elements in an array are properly formatted MD5 hashes
 * <br>
 * <br>Checks if:
 * <br>1. The input is an array
 * <br>2. Every element in the array passes checkMd5val() validation
 * <br>(32-character hexadecimal strings in lowercase)
 *
 * @param {*} arr - The array to validate
 * @returns {boolean} True if all elements are valid MD5 hashes, false otherwise
 *                   (also returns false if input is not an array)
 * @see {@link module:api~checkMd5val|Function CheckMd5Val} for individual MD5 hash validation logic
 *
 * @example
 * checkMd5arr(['d41d8cd98f00b204e9800998ecf8427e', '5d41402abc4b2a76b9719d911017c592']) // true
 * checkMd5arr(['d41d8cd98f00b204e9800998ecf8427e', 'invalid']) // false
 * checkMd5arr('not an array') // false
 * checkMd5arr([]) // false (empty array is considered invalid)
 */
function checkMd5arr(arr) {
    if (!Array.isArray(arr)) return false;
    if (arr.length === 0) return false;
    return arr.every(item => {
        return checkMd5val(item);
    });
}

/**
 * Applies a custom transformation to what appears to be an MD5 hash
 * <br>
 * <br>This function performs a series of reversible transformations on an input string
 * <br>that appears to be an MD5 hash (32 hexadecimal characters). The transformation includes:
 * <br>1. Character restoration at position 9
 * <br>2. XOR operation with position-dependent values
 * <br>3. Byte reordering of the result
 *
 * @param {string} md5 - The input string (expected to be 32 hexadecimal characters)
 * @returns {string} The transformed result (32 hexadecimal characters)
 * @throws Will return the original input unchanged if length is not 32
 *
 * @example
 * decodeMd5('a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6') // returns transformed value
 * decodeMd5('short') // returns 'short' (unchanged)
 */
function decodeMd5(md5) {
    // Return unchanged if not 32 characters
    if (md5.length !== 32) return md5;
    
    // Restore character at position 9
    const restoredHexChar = (md5.charCodeAt(9) - 'g'.charCodeAt(0)).toString(16);
    const o = md5.slice(0, 9) + restoredHexChar + md5.slice(10);
    
    // Apply XOR transformation to each character
    let n = '';
    for (let i = 0; i < o.length; i++) {
        const orig = parseInt(o[i], 16) ^ (i & 15);
        n += orig.toString(16);
    }
    
    // Reorder the bytes in the result
    const e =
        n.slice(8, 16) +  // original bytes 8-15 (now first)
        n.slice(0, 8) +   // original bytes 0-7 (now second)
        n.slice(24, 32) + // original bytes 24-31 (now third)
        n.slice(16, 24);   // original bytes 16-23 (now last)
    
    return e;
}

/**
 * Converts between standard and URL-safe Base64 encoding formats
 * <br>
 * <br>Base64 strings may contain '+', '/' and '=' characters that need to be replaced
 * <br>for safe use in URLs. This function provides bidirectional conversion:
 * <br>- Mode 1: Converts to URL-safe Base64 (RFC 4648 §5)
 * <br>- Mode 2: Converts back to standard Base64
 *
 * @param {string} str - The Base64 string to convert
 * @param {number} [mode=1] - Conversion direction:
 *                            1 = to URL-safe (default),
 *                            2 = to standard
 * @returns {string} The converted Base64 string
 *
 * @example
 * // To URL-safe Base64
 * changeBase64Type('a+b/c=') // returns 'a-b_c='
 *
 * // To standard Base64
 * changeBase64Type('a-b_c=', 2) // returns 'a+b/c='
 *
 * @see {@link https://tools.ietf.org/html/rfc4648#section-5|RFC 4648 §5} for URL-safe Base64
 */
function changeBase64Type(str, mode = 1) {
    return mode === 1
        ? str.replace(/\+/g, '-').replace(/\//g, '_')  // to url-safe
        : str.replace(/-/g,  '+').replace(/_/g,  '/'); // to standard
}

/**
 * Decrypts AES-128-CBC encrypted data using provided parameters
 * <br>
 * <br>This function:
 * <br>1. Converts both parameters from URL-safe Base64 to standard Base64
 * <br>2. Extracts the IV (first 16 bytes) and ciphertext from pp1
 * <br>3. Uses pp2 as the decryption key
 * <br>4. Performs AES-128-CBC decryption
 *
 * @param {string} pp1 - Combined IV and ciphertext in URL-safe Base64 format:
 *                      First 16 bytes are IV, remainder is ciphertext
 * @param {string} pp2 - Encryption key in URL-safe Base64 format
 * @returns {string} The decrypted UTF-8 string
 * @throws {Error} May throw errors for invalid inputs or decryption failures
 *
 * @example
 * // Example usage (with actual encrypted data)
 * const decrypted = decryptAES(
 *     'MTIzNDU2Nzg5MDEyMzQ1Ng==...',  // IV + ciphertext
 *     'c2VjcmV0LWtleS1kYXRhCg=='      // Key
 * );
 *
 * @requires crypto Node.js crypto module
 * @see {@link module:api~changeBase64Type|Function ChangeBase64Type} for Base64 format conversion
 */
function decryptAES(pp1, pp2) {
    // Convert from URL-safe Base64 to standard Base64
    pp1 = changeBase64Type(pp1, 2);
    pp2 = changeBase64Type(pp2, 2);
    
    // Extract ciphertext (after first 16 bytes) and IV (first 16 bytes)
    const cipherText = pp1.substring(16);
    const key = Buffer.from(pp2, 'utf8');
    const iv = Buffer.from(pp1.substring(0, 16), 'utf8');
    
    // Create decipher with AES-128-CBC algorithm
    const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
    
    // Perform decryption
    let decrypted = decipher.update(cipherText, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
}

/**
 * Encrypts data using RSA with a public key, with optional MD5 preprocessing
 * <br>
 * <br>Supports two encryption modes:
 * <br>1. Direct encryption of the message (default)
 * <br>2. MD5 hash preprocessing (applies MD5 + length padding before encryption)
 *
 * @param {string} message - The plaintext message to encrypt
 * @param {string|Buffer} publicKeyPEM - RSA public key in PEM format
 * @param {number} [mode=1] - Encryption mode:
 *                            1 = direct encryption,
 *                            2 = MD5 hash preprocessing
 * @returns {string} Base64-encoded encrypted data
 * @throws {Error} May throw errors for invalid keys or encryption failures
 *
 * @example
 * // Direct encryption
 * encryptRSA('secret message', publicKey);
 *
 * // With MD5 preprocessing
 * encryptRSA('secret message', publicKey, 2);
 *
 * @requires crypto Node.js crypto module
 */
function encryptRSA(message, publicKeyPEM, mode = 1) {
    // Mode 2: Apply MD5 hash and length padding
    if (mode === 2) {
        const md5 = crypto.createHash('md5').update(message).digest('hex');
        message = md5 + (md5.length<10?'0':'') + md5.length;
    }
    
    // Convert message to Buffer
    const buffer = Buffer.from(message, 'utf8');
    
    // Perform RSA encryption
    const encrypted = crypto.publicEncrypt({
        key: publicKeyPEM,
        padding: crypto.constants.RSA_PKCS1_PADDING,
    }, buffer);
    
    // Return as Base64 string
    return encrypted.toString('base64');
}

/**
 * Generates a pseudo-random SHA-1 hash from combined client parameters
 * <br>
 * <br>Creates a deterministic hash value by combining multiple client-specific parameters.
 * <br>This is typically used for generating session tokens or unique identifiers.
 *
 * @param {string} [client='web'] - Client identifier (e.g., 'web', 'mobile')
 * @param {string} seval - Session evaluation parameter
 * @param {string} encpwd - Encrypted password or password hash
 * @param {string} email - User's email address
 * @param {string} [browserid=''] - Browser fingerprint or identifier
 * @param {string} random - Random value
 * @returns {string} SHA-1 hash of the combined parameters (40-character hex string)
 *
 * @example
 * // Basic usage
 * const token = prandGen('web', 'session123', 'encryptedPwd', 'user@example.com', 'browser123', 'randomValue');
 *
 * // With default client and empty browserid
 * const token = prandGen(undefined, 'session123', 'encryptedPwd', 'user@example.com', '', 'randomValue');
 *
 * @requires crypto Node.js crypto module
 */
function prandGen(client = 'web', seval, encpwd, email, browserid = '', random) {
    // Combine all parameters with hyphens
    const combined = `${client}-${seval}-${encpwd}-${email}-${browserid}-${random}`;
    
    // Generate SHA-1 hash and return as hex string
    return crypto.createHash('sha1').update(combined).digest('hex');
}

/**
 * TeraBoxApp API client class
 *
 * Provides a comprehensive interface for interacting with TeraBox services,
 * including encryption utilities, API request handling, and session management.
 *
 * @class
 * @property {module:api~FormUrlEncoded   } FormUrlEncoded - Form URL encoding utility
 * @property {module:api~signDownload     } SignDownload - Download signature generator
 * @property {module:api~checkMd5val      } CheckMd5Val - MD5 hash validator (single)
 * @property {module:api~checkMd5arr      } CheckMd5Arr - MD5 hash validator (array)
 * @property {module:api~decodeMd5        } DecodeMd5 - Custom MD5 transformation
 * @property {module:api~changeBase64Type } ChangeBase64Type - Base64 format converter
 * @property {module:api~decryptAES       } DecryptAES - AES decryption utility
 * @property {module:api~encryptRSA       } EncryptRSA - RSA encryption utility
 * @property {module:api~prandGen         } PRandGen - Pseudo-random hash generator
 *
 * @property {string} TERABOX_DOMAIN - Default TeraBox domain
 * @property {number} TERABOX_TIMEOUT - Default API timeout (10 seconds)
 *
 * @property {Object} data - Application data including tokens and keys
 * @property {string} data.csrf - CSRF token
 * @property {string} data.logid - Log ID
 * @property {string} data.pcftoken - PCF token
 * @property {string} data.bdstoken - BDS token
 * @property {string} data.jsToken - JavaScript token
 * @property {string} data.pubkey - Public key
 *
 * @property {TeraBoxAppParams} params - Application parameters and configuration
 */
class TeraBoxApp {
    // Encryption/Utility Methods 1
    FormUrlEncoded = FormUrlEncoded;
    SignDownload = signDownload;
    CheckMd5Val = checkMd5val;
    CheckMd5Arr = checkMd5arr;
    DecodeMd5 = decodeMd5;
    
    // Encryption/Utility Methods 2
    ChangeBase64Type = changeBase64Type;
    DecryptAES = decryptAES;
    EncryptRSA = encryptRSA;
    PRandGen = prandGen;
    
    // Constants
    TERABOX_DOMAIN = 'terabox.com';
    TERABOX_TIMEOUT = 10000;
    
    // app data
    data = {
        csrf: '',
        logid: '0',
        pcftoken: '',
        bdstoken: '',
        jsToken: '',
        pubkey: '',
    };
    
    // Application parameters and configuration
    params = {
        whost: 'https://www.' + this.TERABOX_DOMAIN,
        uhost: 'https://c-jp.' + this.TERABOX_DOMAIN,
        lang: 'en',
        app: {
            app_id: 250528,
            web: 1,
            channel: 'dubox',
            clienttype: 0, // 5 is wap?
        },
        ver_android: '3.44.2',
        ua: 'terabox;1.40.0.132;PC;PC-Windows;10.0.26100;WindowsTeraBox',
        cookie: '',
        auth: {},
        account_id: 0,
        account_name: '',
        is_vip: false,
        vip_type: 0,
        space_used: 0,
        space_total: Math.pow(1024, 3),
        space_available: Math.pow(1024, 3),
        cursor: 'null',
    };
    
    /**
     * Creates a new TeraBoxApp instance
     * @param {string} authData - Authentication data (NDUS token)
     * @param {string} [authType='ndus'] - Authentication type (currently only 'ndus' supported)
     * @throws {Error} Throws error if authType is not supported
     */
    constructor(authData, authType = 'ndus') {
        this.params.cookie = `lang=${this.params.lang}`;
        if(authType === 'ndus'){
            this.params.cookie += authData ? '; ndus=' + authData : '';
        }
        else{
            throw new Error('initTBApp', { cause: 'AuthType Not Supported!' });
        }
    }
    
    /**
     * Updates application data including tokens and user information
     * @param {string} [customPath] - Custom path to use for the update request
     * @param {number} [retries=4] - Number of retry attempts
     * @returns {Promise<Object>} The updated template data
     * @async
     * @throws {Error} Throws error if request fails or parsing fails
     */
    async updateAppData(customPath, retries = 4){
        const url = new URL(this.params.whost + (customPath ? `/${customPath}` : '/main'));
        
        try{
            const req = await request(url, {
                headers:{
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT + 10000),
            });
            
            if(req.statusCode === 302){
                if(req.headers.location === '/login'){
                    req.headers.location = this.params.whost + '/login';
                }
                const newUrl = new URL(req.headers.location);
                if(this.params.whost !== newUrl.origin){
                    this.params.whost = newUrl.origin;
                    console.warn(`[WARN] Default hostname changed to ${newUrl.origin}`);
                }
                const toPathname = newUrl.pathname.replace(/^\//, '');
                const finalUrl = toPathname + newUrl.search;
                return await this.updateAppData(finalUrl, retries);
            }
            
            if(req.headers['set-cookie']){
                const cJar = new CookieJar();
                this.params.cookie.split(';').map(cookie => cJar.setCookieSync(cookie, this.params.whost));
                if(typeof req.headers['set-cookie'] === 'string'){
                    req.headers['set-cookie'] = [req.headers['set-cookie']];
                }
                for(const cookie of req.headers['set-cookie']){
                    cJar.setCookieSync(cookie.split('; ')[0], this.params.whost);
                }
                this.params.cookie = cJar.getCookiesSync(this.params.whost).map(cookie => cookie.cookieString()).join('; ');
            }
            
            const rdata = await req.body.text();
            const tdataRegex = /<script>var templateData = (.*);<\/script>/;
            const jsTokenRegex = /window.jsToken%20%3D%20a%7D%3Bfn%28%22(.*)%22%29/;
            const tdata = rdata.match(tdataRegex) ? JSON.parse(rdata.match(tdataRegex)[1].split(';</script>')[0]) : {};
            const isLoginReq = req.headers.location === '/login' ? true : false;
            
            if(tdata.jsToken){
                tdata.jsToken = tdata.jsToken.match(/%28%22(.*)%22%29/)[1];
            }
            else if(rdata.match(jsTokenRegex)){
                tdata.jsToken = rdata.match(jsTokenRegex)[1];
            }
            else if(isLoginReq){
                console.error('[ERROR] Failed to update jsToken [Login Required]');
            }
            
            if(req.headers.logid){
                this.data.logid = req.headers.logid;
            }
            
            this.data.csrf = tdata.csrf || '';
            this.data.pcftoken = tdata.pcftoken || '';
            this.data.bdstoken = tdata.bdstoken || '';
            this.data.jsToken = tdata.jsToken || '';
            
            this.params.account_id = parseInt(tdata.uk) || 0;
            if(typeof tdata.userVipIdentity === 'number' && tdata.userVipIdentity > 0){
                this.params.is_vip = true;
                this.params.vip_type = 1;
            }
            
            return tdata;
        }
        catch(error){
            if(error.name === 'TimeoutError' && retries > 0){
                await new Promise(resolve => setTimeout(resolve, 500));
                return await this.updateAppData(customPath, retries - 1);
            }
            const errorPrefix = '[ERROR] Failed to update jsToken:';
            if(error.name === 'TimeoutError'){
                console.error(errorPrefix, error.message);
                return;
            }
            const errorReturn = new Error('updateAppData', { cause: error });
            console.error(errorPrefix, errorReturn);
        }
    }
    
    /**
     * Sets default VIP parameters
     * @returns {void}
     */
    setVipDefaults(){
        this.params.is_vip = true;
        this.params.vip_type = 1; // 1: VIP, 2: SVIP
        this.params.space_total = Math.pow(1024, 3) * 2;
        this.params.space_available = Math.pow(1024, 3) * 2;
    }
    
    /**
     * Makes an API request with retry logic
     * @param {string} req_url - The request URL (relative to whost)
     * @param {Object} [req_options={}] - Request options (headers, body, etc.)
     * @param {number} [retries=4] - Number of retry attempts
     * @returns {Promise<Object>} The JSON-parsed response data
     * @async
     * @throws {Error} Throws error if all retries fail
     */
    async doReq(req_url, req_options = {}, retries = 4){
        const url = new URL(this.params.whost + req_url);
        let reqm_options = structuredClone(req_options);
        let req_headers = {};
        
        if(reqm_options.headers){
            req_headers = reqm_options.headers;
            delete reqm_options.headers;
        }
        
        const save_cookies = reqm_options.save_cookies;
        delete reqm_options.save_cookies;
        const silent_retry = reqm_options.silent_retry;
        delete reqm_options.silent_retry;
        const req_timeout = reqm_options.timeout ? reqm_options.timeout : this.TERABOX_TIMEOUT;
        delete reqm_options.timeout;
        
        try {
            const options = {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                    ...req_headers,
                },
                ...reqm_options,
                signal: AbortSignal.timeout(req_timeout),
            };
            
            const req = await request(url, options);
            
            if(save_cookies && req.headers['set-cookie']){
                const cJar = new CookieJar();
                this.params.cookie.split(';').map(cookie => cJar.setCookieSync(cookie, this.params.whost));
                if(typeof req.headers['set-cookie'] === 'string'){
                    req.headers['set-cookie'] = [req.headers['set-cookie']];
                }
                for(const cookie of req.headers['set-cookie']){
                    cJar.setCookieSync(cookie.split('; ')[0], this.params.whost);
                }
                this.params.cookie = cJar.getCookiesSync(this.params.whost).map(cookie => cookie.cookieString()).join('; ');
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch(error){
            if (retries > 0) {
                await new Promise(resolve => setTimeout(resolve, 500));
                if(!silent_retry){
                    console.error('[ERROR] DoReq:', req_url, '|', error.code, ':', error.message, '(retrying...)');
                }
                return await this.doReq(req_url, req_options, retries - 1);
            }
            throw new Error('doReq', { cause: error });
        }
    }
    
    /**
     * Retrieves system configuration from the TeraBox API
     * @returns {Promise<Object>} The system configuration JSON data
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async getSysCfg(){
        const url = new URL(this.params.whost + '/api/getsyscfg');
        url.search = new URLSearchParams({
            clienttype: this.params.app.clienttype,
            language_type: this.params.lang,
            cfg_category_keys: '[]',
            version: 0,
        });
        
        try{
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    // 'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch(error){
            throw new Error('getSysCfg', { cause: error });
        }
    }
    
    /**
     * Checks login status of the current session.
     * @returns {Promise<CheckLoginResponse>} The login status JSON data.
     * @throws {Error} Throws error if HTTP status is not 200 or request fails.
     * @async
     */
    async checkLogin(){
        const url = new URL(this.params.whost + '/api/check/login');
        
        try{
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const regionPrefix = req.headers['region-domain-prefix'];
            if(regionPrefix){
                const newHostname = `https://${regionPrefix}.${this.TERABOX_DOMAIN}`;
                console.warn(`[WARN] Default hostname changed to ${newHostname}`);
                this.params.whost = new URL(newHostname).origin;
                return await this.checkLogin();
            }
            
            const rdata = await req.body.json();
            if(rdata.errno === 0){
                this.params.account_id = rdata.uk;
            }
            return rdata;
        }
        catch(error){
            throw new Error('checkLogin', { cause: error });
        }
    }
    
    /**
     * Initiates the pre-login step for passport authentication
     * @param {string} email - The user's email address
     * @returns {Promise<Object>} The pre-login data JSON (includes seval, random, timestamp)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async passportPreLogin(email){
        const url = new URL(this.params.whost + '/passport/prelogin');
        const authUrl = 'wap/outlogin/login';
        
        try{
            if(this.data.pcftoken === ''){
                await this.updateAppData(authUrl);
            }
            
            const formData = new this.FormUrlEncoded();
            formData.append('client', 'web');
            formData.append('pass_version', '2.8');
            formData.append('clientfrom', 'h5');
            formData.append('pcftoken', this.data.pcftoken);
            formData.append('email', email);
            
            const req = await request(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                    Referer: this.params.whost,
                },
                body: formData.str(),
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('passportPreLogin', { cause: error });
        }
    }
    
    /**
     * Completes the passport login process using preLoginData and password
     * @param {Object} preLoginData - Data returned from passportPreLogin
     * @param {string} preLoginData.seval - The seval value from pre-login.
     * @param {string} preLoginData.random - The random value from pre-login.
     * @param {number} preLoginData.timestamp - The timestamp from pre-login.
     * @param {string} email - The user's email address
     * @param {string} pass - The user's plaintext password
     * @returns {Promise<Object>} The login response JSON (includes ndus token on success)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async passportLogin(preLoginData, email, pass){
        const url = new URL(this.params.whost + '/passport/login');
        
        try{
            if(this.data.pubkey === ''){
                await this.getPublicKey();
            }
            
            const cJar = new CookieJar();
            this.params.cookie.split(';').map(cookie => cJar.setCookieSync(cookie, this.params.whost));
            const browserid = cJar.toJSON().cookies.find(c => c.key === 'browserid').value || '';
            const encpwd = this.ChangeBase64Type(this.EncryptRSA(pass, this.data.pubkey, 2));
            
            const prand = this.PRandGen('web', preLoginData.seval, encpwd, email, browserid, preLoginData.random);
            
            const formData = new this.FormUrlEncoded();
            formData.append('client', 'web');
            formData.append('pass_version', '2.8');
            formData.append('clientfrom', 'h5');
            formData.append('pcftoken', this.data.pcftoken);
            formData.append('prand', prand);
            formData.append('email', email);
            formData.append('pwd', encpwd);
            formData.append('seval', preLoginData.seval);
            formData.append('random', preLoginData.random);
            formData.append('timestamp', preLoginData.timestamp);
            
            const req = await request(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                    Referer: this.params.whost,
                },
                body: formData.str(),
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            if(rdata.code === 0){
                if(typeof req.headers['set-cookie'] === 'string'){
                    req.headers['set-cookie'] = [req.headers['set-cookie']];
                }
                for(const cookie of req.headers['set-cookie']){
                    cJar.setCookieSync(cookie.split('; ')[0], this.params.whost);
                }
                const ndus = cJar.toJSON().cookies.find(c => c.key === 'ndus').value;
                rdata.data.ndus = ndus;
            }
            return rdata;
        }
        catch (error) {
            throw new Error('passportLogin', { cause: error });
        }
    }
    
    /**
     * Sends a registration code to the specified email
     * @param {string} email - The email address to send the code to
     * @returns {Promise<Object>} The send code response JSON (includes code and message)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async regSendCode(email){
        const url = new URL(this.params.whost + '/passport/register_v4/sendcode');
        const emailRegUrl = 'wap/outlogin/emailRegister';
        
        try{
            if(this.data.pcftoken === ''){
                await this.updateAppData(emailRegUrl);
            }
            
            const formData = new this.FormUrlEncoded();
            formData.append('client', 'web');
            formData.append('pass_version', '2.8');
            formData.append('clientfrom', 'h5');
            formData.append('pcftoken', this.data.pcftoken);
            formData.append('email', email);
            
            const req = await request(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                    Referer: this.params.whost,
                },
                body: formData.str(),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            // rdata.code: 0 - OK
            // rdata.code: 10 - Email format invalid
            // rdata.code: 11 - Email has been register before
            // rdata.code: 60 - Send code too fast, wait ~60sec
            return rdata;
        }
        catch (error) {
            throw new Error('regSendCode', { cause: error });
        }
    }
    
    /**
     * Verifies the registration code received via email
     * @param {string} regToken - Registration token from send code response
     * @param {string|number} code - The verification code sent to email
     * @returns {Promise<Object>} The verification response JSON
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async regVerify(regToken, code){
        const url = new URL(this.params.whost + '/passport/register_v4/verify');
        
        try{
            const formData = new this.FormUrlEncoded();
            formData.append('client', 'web');
            formData.append('pass_version', '2.8');
            formData.append('clientfrom', 'h5');
            formData.append('pcftoken', this.data.pcftoken);
            formData.append('token', regToken);
            formData.append('code', code);
            
            const req = await request(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                    Referer: this.params.whost,
                },
                body: formData.str(),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            // rdata.code: 0 - OK
            // rdata.code: 59 - Email code is wrong
            return rdata;
        }
        catch (error) {
            throw new Error('regVerify', { cause: error });
        }
    }
    
    /**
     * Completes the registration process by setting a password
     * @param {string} regToken - Registration token from verification step
     * @param {string} pass - The new password to set, length is 6-15 and contains at least 1 Latin letter
     * @returns {Promise<Object>} The finish registration response JSON (includes ndus token on success)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async regFinish(regToken, pass){
        const url = new URL(this.params.whost + '/passport/register_v4/finish');
        
        try{
            if(this.data.pubkey === ''){
                await this.getPublicKey();
            }
            
            if(typeof pass !== 'string' || pass.length < 6 || pass.length > 15 || !pass.match(/[a-z]/i)){
                return { code: -2, logid: 0, msg: 'invalid password', };
            }
            
            const encpwd = this.ChangeBase64Type(this.EncryptRSA(pass, this.data.pubkey, 2));
            
            const formData = new this.FormUrlEncoded();
            formData.append('client', 'web');
            formData.append('pass_version', '2.8');
            formData.append('clientfrom', 'h5');
            formData.append('pcftoken', this.data.pcftoken);
            formData.append('token', regToken);
            formData.append('pwd', encpwd);
            
            const req = await request(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                    Referer: this.params.whost,
                },
                body: formData.str(),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            if(rdata.code === 0 && req.headers['set-cookie']){
                const cJar = new CookieJar();
                
                if(typeof req.headers['set-cookie'] === 'string'){
                    req.headers['set-cookie'] = [req.headers['set-cookie']];
                }
                for(const cookie of req.headers['set-cookie']){
                    cJar.setCookieSync(cookie.split('; ')[0], this.params.whost);
                }
                
                const ndus = cJar.toJSON().cookies.find(c => c.key === 'ndus').value;
                rdata.data.ndus = ndus;
            }
            return rdata;
        }
        catch (error) {
            throw new Error('regFinish', { cause: error });
        }
    }
    
    /**
     * Retrieves passport user information for the current session
     * @returns {Promise<Object>} The passport user info JSON (includes display_name)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async passportGetInfo(){
        const url = new URL(this.params.whost + '/passport/get_info');
        
        try{
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            if(rdata.errno === 0){
                this.params.account_name = rdata.data.display_name;
            }
            return rdata;
        }
        catch (error) {
            throw new Error('getPassport', { cause: error });
        }
    }
    
    /**
     * Fetches membership information for the current user
     * @returns {Promise<Object>} The membership JSON (includes VIP status)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async userMembership(){
        const url = new URL(this.params.whost + '/rest/2.0/membership/proxy/user');
        url.search = new URLSearchParams({
            method: 'query',
        });
        
        try{
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            if(rdata.error_code === 0){
                this.params.is_vip = rdata.data.member_info.is_vip > 0 ? true : false;
                // this.params.vip_type = this.params.is_vip ? 2 : 0;
                if(this.params.is_vip === 0){
                    this.params.vip_type = 0;
                }
            }
            return rdata;
        }
        catch(error){
            throw new Error('userMembership', { cause: error });
        }
    }
    
    /**
     * Retrieves current user information (username, VIP status)
     * @returns {Promise<Object>} The user info JSON (includes records array)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async getCurrentUserInfo(){
        try{
            if(this.params.account_id === 0){
                await this.checkLogin();
            }
            
            const curUser = await this.getUserInfo(this.params.account_id);
            if(curUser.records.length > 0){
                const thisUser = curUser.records[0];
                this.params.account_name = thisUser.uname;
                this.params.is_vip = thisUser.vip_type > 0 ? true : false;
                this.params.vip_type = thisUser.vip_type;
            }
            return curUser;
        }
        catch (error) {
            throw new Error('getCurrentUserInfo', { cause: error });
        }
    }
    
    /**
     * Retrieves information for a specific user ID
     * @param {number|string} user_id - The user ID to look up
     * @returns {Promise<Object>} The user info JSON (includes data)
     * @async
     * @throws {Error} Throws error if user_id is invalid, HTTP status is not 200, or request fails
     */
    async getUserInfo(user_id){
        user_id = parseInt(user_id);
        const url = new URL(this.params.whost + '/api/user/getinfo');
        url.search = new URLSearchParams({
            user_list: JSON.stringify([user_id]),
            need_relation: 0,
            need_secret_info: 1,
        });
        
        try{
            if(isNaN(user_id) || !Number.isSafeInteger(user_id)){
                throw new Error(`${user_id} is not user id`);
            }
            
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('getUserInfo', { cause: error });
        }
    }
    
    /**
     * Retrieves storage quota information for the current account
     * @returns {Promise<Object>} The quota JSON (includes total, used, available)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async getQuota(){
        const url = new URL(this.params.whost + '/api/quota');
        url.search = new URLSearchParams({
            checkexpire: 1,
            checkfree: 1,
        });
        
        try{
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            if(rdata.errno === 0){
                rdata.available = rdata.total - rdata.used;
                this.params.space_available = rdata.available;
                this.params.space_total = rdata.total;
                this.params.space_used = rdata.used;
            }
            return rdata;
        }
        catch (error) {
            throw new Error('getQuota', { cause: error });
        }
    }
    
    /**
     * Retrieves the user's coins count (points)
     * @returns {Promise<Object>} The coins count JSON (includes records of coin usage)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async getCoinsCount(){
        const url = new URL(this.params.whost + '/rest/1.0/inte/system/getrecord');
        
        try{
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('getCoinsCount', { cause: error });
        }
    }
    
    /**
     * Retrieves the contents of a remote directory
     * @param {string} remoteDir - Remote directory path to list
     * @param {number} [page=1] - Page number for pagination
     * @returns {Promise<Object>} The directory listing JSON (includes entries array)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async getRemoteDir(remoteDir, page = 1){
        const url = new URL(this.params.whost + '/api/list');
        
        try{
            const formData = new this.FormUrlEncoded();
            formData.append('order', 'name');
            formData.append('desc', 0);
            formData.append('dir', remoteDir);
            formData.append('num', 20000);
            formData.append('page', page);
            formData.append('showempty', 0);
            
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('getRemoteDir', { cause: error });
        }
    }
    
    /**
     * Retrieves the contents of a remote directory with specific file category
     * @param {number} [categoryId=1] - selected category:
     *     <br>1: video
     *     <br>2: audio
     *     <br>3: pictures
     *     <br>4: documents
     *     <br>5: apps
     *     <br>6: other
     *     <br>7: torrent
     * @param {string} remoteDir - Remote directory path to list
     * @param {number} [page=1] - Page number for pagination
     * @returns {Promise<Object>} The directory listing JSON (includes entries array)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async getCategoryList(categoryId = 1, remoteDir = '/', page = 1, order = 'name', desc = 0, num = 20000){
        const url = new URL(this.params.whost + '/api/categorylist');
        
        try{
            const formData = new this.FormUrlEncoded();
            formData.append('order', order);
            formData.append('desc', desc);
            formData.append('dir', remoteDir);
            formData.append('num', num);
            formData.append('page', page);
            formData.append('category', categoryId);
            
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('getCategoryList', { cause: error });
        }
    }
    
    /**
     * Retrieves the contents of the recycle bin
     * @returns {Promise<Object>} The recycle bin listing JSON (includes entries array)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async getRecycleBin(page = 1){
        const url = new URL(this.params.whost + '/api/recycle/list');
        
        try{
            url.search = new URLSearchParams({
                // order: 'name',
                desc: 0,
                num: 20000,
                page: page,
            });
            
            
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('getRecycleBin', { cause: error });
        }
    }
    
    /**
     * Clears all items in the recycle bin
     * @returns {Promise<Object>} The clear recycle bin response JSON
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async clearRecycleBin(){
        const url = new URL(this.params.whost + '/api/recycle/clear');
        
        try{
            url.search = new URLSearchParams({
                'async': 1,
            });
            
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('clearRecycleBin', { cause: error });
        }
    }
    
    /**
     * Initiates a precreate request for a file (reserve upload ID and pre-upload checks)
     * @param {Object} data - File data including remote_dir, file, size, upload_id (optional), and hash info
     * @param {string} data.remote_dir - Remote directory path
     * @param {string} data.file - Filename
     * @param {number} data.size - File size in bytes
     * @param {string} [data.upload_id] - Existing upload ID for resuming
     * @param {Object} data.hash - Hash information
     * @param {string} data.hash.file - MD5 hash of full file
     * @param {string} data.hash.slice - MD5 hash of first slice
     * @param {number} data.hash.crc32 - CRC32 value
     * @param {Array<string>} data.hash.chunks - Array of MD5 chunk hashes
     * @returns {Promise<Object>} The precreate response JSON (includes upload_id, etc.)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async precreateFile(data){
        const formData = new this.FormUrlEncoded();
        formData.append('path', makeRemoteFPath(data.remote_dir, data.file));
        // formData.append('target_path', data.remote_dir);
        formData.append('autoinit', 1);
        formData.append('size', data.size);
        formData.append('file_limit_switch_v34', 'true');
        formData.append('block_list', '[]');
        formData.append('rtype', 2);
        
        if(data.upload_id && typeof data.upload_id === 'string' && data.upload_id !== ''){
            formData.append('uploadid', data.upload_id);
        }
        
        // check if has correct md5 values
        if(this.CheckMd5Val(data.hash.slice) && this.CheckMd5Val(data.hash.file)){
            formData.append('content-md5', data.hash.file);
            formData.append('slice-md5', data.hash.slice);
        }
        
        // check crc32int and ignore field for crc32 out of range
        if(Number.isSafeInteger(data.hash.crc32) && data.hash.crc32 >= 0 && data.hash.crc32 <= 0xFFFFFFFF){
            formData.append('content-crc32', data.hash.crc32);
        }
        
        // check chunks hash
        if(!this.CheckMd5Arr(data.hash.chunks)){
            const predefinedHash = ['5910a591dd8fc18c32a8f3df4fdc1761'];
            
            if(data.size > 4 * 1024 * 1024){
                predefinedHash.push('a5fc157d78e6ad1c7e114b056c92821e');
            }
            
            formData.set('block_list', JSON.stringify(predefinedHash));
        }
        else{
            formData.set('block_list', JSON.stringify(data.hash.chunks));
        }
        
        // formData.append('local_ctime', '');
        // formData.append('local_mtime', '');
        
        const url = new URL(this.params.whost + '/api/precreate');
        
        try{
            if(this.data.jsToken === ''){
                await this.updateAppData();
            }
            
            url.search = new URLSearchParams({
                ...this.params.app,
                jsToken: this.data.jsToken,
            });
            
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            // uploadid	= 'P1-' + BASE64(ServerLocalIP + ':' + ServerTime + ':' + RequestID)
            const rdata = await req.body.json();
            // rdata.errno: 4000023 - need verify
            if(rdata.errno === 4000023){
                await this.updateAppData();
                return await this.precreateFile(data);
            }
            return rdata;
        }
        catch (error) {
            throw new Error('precreateFile', { cause: error });
        }
    }
    
    /**
     * Attempts a rapid upload using existing file hashes (skip actual upload if file already on server)
     * @param {Object} data - File data including remote_dir, file, size, and hash info
     * @param {string} data.remote_dir - Remote directory path
     * @param {string} data.file - Filename
     * @param {number} data.size - File size in bytes
     * @param {Object} data.hash - Hash information
     * @param {string} data.hash.file - MD5 hash of full file
     * @param {string} data.hash.slice - MD5 hash of first slice
     * @param {number} data.hash.crc32 - CRC32 value
     * @param {Array<string>} [data.hash.chunks] - Array of MD5 chunk hashes
     * @returns {Promise<Object>} The rapid upload response JSON (indicates success or fallback)
     * @async
     * @throws {Error} Throws error if file size < 256KB, invalid hashes, HTTP status is not 200, or request fails
     */
    async rapidUpload(data){
        const formData = new this.FormUrlEncoded({
            path:  makeRemoteFPath(data.remote_dir, data.file),
            //target_path: data.remote_dir
            'content-length': data.size,
            'content-md5': data.hash.file,
            'slice-md5': data.hash.slice,
            'content-crc32': data.hash.crc32,
            //local_ctime: '',
            //local_mtime: '',
            block_list: JSON.stringify(data.hash.chunks || []),
            rtype: 2,
            mode: 1,
        });
        
        if(!this.CheckMd5Val(data.hash.slice) || !this.CheckMd5Val(data.hash.file)){
            const badMD5 = new Error('Bad MD5 Slice Hash or MD5 File Hash');
            throw new Error('rapidUpload', { cause: badMD5 });
        }
        
        if(!Number.isSafeInteger(data.hash.crc32) || data.hash.crc32 < 0 || data.hash.crc32 > 0xFFFFFFFF){
            formData.delete('content-crc32');
        }
        
        if(!this.CheckMd5Arr(data.hash.chunks)){
            // use unsafe rapid upload if we don't have chunks hash
            formData.delete('block_list');
            formData.set('rtype', 3);
        }
        
        const url = new URL(this.params.whost + '/api/rapidupload');
        
        try{
            if(data.size < 256 * 1024){
                throw new Error('File size too small!');
            }
            
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            // rdata.errno: 2 - already exist?
            return rdata;
        }
        catch (error) {
            throw new Error('rapidUpload', { cause: error });
        }
    }
    
    /**
     * Cloud_DL service: Get task list
     * @returns {Promise<Object>} Cloud_DL service task list JSON
     * @async
     * @throws {Error} Throws error if HTTP status is not 200, or request fails
     */
    async clouddl_tasklist(){
        const formData = new this.FormUrlEncoded({
            method: 'list_task',
            // limit: 20,
            // start: 0,
            need_task_info: 1,
            // status: 255,
        });
        
        const url = new URL(this.params.whost + '/rest/2.0/services/cloud_dl');
        
        try{
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('clouddl_tasklist', { cause: error });
        }
    }
    
    /**
     * Cloud_DL service: Query task info
     * @param {string} task_id - Task ID info
     * @returns {Promise<Object>} Cloud_DL service task info JSON
     * @async
     * @throws {Error} Throws error if HTTP status is not 200/403, or request fails
     */
    async clouddl_query_task(task_id){
        const formData = new this.FormUrlEncoded({
            method: 'query_task',
            task_ids: task_id,
            op_type: 1,
        });
        
        const url = new URL(this.params.whost + '/rest/2.0/services/cloud_dl');
        
        try{
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (![200, 403].includes(req.statusCode)) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('clouddl_query_task', { cause: error });
        }
    }
    
    /**
     * Cloud_DL service: Add task
     * @param {string} source       - remote torrent file path or magnet link
     * @param {string} sha1hash     - torrent hash (fetch it from clouddl_query_sinfo), empty string for magnet
     * @param {string} save_path    - remote save path
     * @param {string} selected_idx - select file indexes from torrent file / magnet (comma-separated with starting index 1)
     * @returns {Promise<Object>} Cloud_DL service task list JSON
     * @async
     * @throws {Error} Throws error if HTTP status is not 200/400/403/500, or request fails
     */
    async clouddl_add_task(source = '', sha1hash = '', selected_idx, save_path){
        const formData = new this.FormUrlEncoded({
            method: 'add_task',
            save_path: save_path,
            selected_idx: selected_idx,
        });
        
        if(typeof source === 'string' && source.trim().toLowerCase().startsWith('magnet:?xt=urn:btih:')){
            formData.append('task_from', '1');
            formData.append('source_url', source);
            formData.append('file_sha1', '');
            formData.append('type', '4'); // 4 is magnet link
            
        }
        else{
            formData.append('task_from', '2');
            formData.append('source_path', source);
            formData.append('file_sha1', sha1hash);
            formData.append('type', '2'); // 2 is torrent file
        }
        
        // alternative url is https://od.terabox.com/api/od_dl
        const url = new URL(this.params.whost + '/rest/2.0/services/cloud_dl');
        
        url.search = new URLSearchParams({
            ...this.params.app,
            jsToken: this.data.jsToken,
            bdstoken: this.data.bdstoken,
        });
        
        try{
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (![200, 400, 403, 500].includes(req.statusCode)) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('clouddl_add_task', { cause: error });
        }
    }
    
    /**
     * Cloud_DL service: Query torrent file info
     * @param {string} source_path - file path to the torrent file on TB drive
     * @returns {Promise<Object>} Cloud_DL magnet link info JSON
     * @async
     * @throws {Error} Throws error if HTTP status is not 200/403/404/500, or request fails
     */
    async clouddl_query_sinfo(source_path){
        const url = new URL(this.params.whost + '/rest/2.0/services/cloud_dl');
        
        url.search = new URLSearchParams({
            method: 'query_sinfo',
            ...this.params.app,
            //jsToken: this.data.jsToken,
            //bdstoken: this.data.bdstoken,
            source_path: source_path,
            type: 2,
        });
        
        try{
            const req = await request(url, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (![200, 403, 404, 500].includes(req.statusCode)) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('clouddl_query_sinfo', { cause: error });
        }
    }
    
    /**
     * Cloud_DL service: Query magnet link info
     * @param {string} magnet_link - magnet link url
     * @returns {Promise<Object>} Cloud_DL magnet link info JSON
     * @async
     * @throws {Error} Throws error if HTTP status is not 200/403, or request fails
     */
    async clouddl_query_magnetinfo(magnet_link){
        const formData = new this.FormUrlEncoded({
            method: 'query_magnetinfo',
            source_url: magnet_link,
            type: 4,
        });
        
        const url = new URL(this.params.whost + '/rest/2.0/services/cloud_dl');
        
        try{
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (![200, 403].includes(req.statusCode)) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('clouddl_query_magnetinfo', { cause: error });
        }
    }
    
    /**
     * Retrieves an upload host endpoint to use for file uploads
     * @returns {Promise<Object>} The upload host response JSON (includes host field)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async getUploadHost(){
        const url = new URL(this.params.whost + '/rest/2.0/pcs/file?method=locateupload');
        try{
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            this.params.uhost = 'https://' + rdata.host;
            return rdata;
        }
        catch (error) {
            throw new Error('getUploadHost', { cause: error });
        }
    }
    
    /**
     * Uploads a single chunk (part) of a file
     * @param {Object} data - File data including remote_dir, file, upload_id
     * @param {number} partseq - The sequence number of this chunk (0-based)
     * @param {Blob|Buffer} blob - The binary data of the chunk
     * @param {function} [reqHandler] - Optional request progress handler
     * @param {AbortSignal} [externalAbort] - Optional external abort signal
     * @returns {Promise<Object>} The upload chunk response JSON (includes MD5 for chunk)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200, chunk upload fails, or request times out
     */
    async uploadChunk(data, partseq, blob, reqHandler, externalAbort) {
        const timeoutAborter = new AbortController;
        const timeoutId = setTimeout(() => { timeoutAborter.abort(); }, this.TERABOX_TIMEOUT);
        externalAbort = externalAbort ? externalAbort : new AbortController().signal;
        
        const url = new URL(`${this.params.uhost}/rest/2.0/pcs/superfile2`);
        url.search = new URLSearchParams({
            method: 'upload',
            ...this.params.app,
            // type: 'tmpfile',
            path: makeRemoteFPath(data.remote_dir, data.file),
            uploadid: data.upload_id,
            // uploadsign: 0,
            partseq: partseq,
        });
        
        const formData = new FormData();
        formData.append('file', blob, 'blob');
        
        const req = await request(url, {
            method: 'POST',
            body: formData,
            headers: {
                'User-Agent': this.params.ua,
                'Cookie': this.params.cookie,
            },
            signal: AbortSignal.any([
                externalAbort,
                timeoutAborter.signal,
            ]),
        });
        
        clearTimeout(timeoutId);
        
        if (req.statusCode !== 200) {
            throw new Error(`HTTP error! Status: ${req.statusCode}`);
        }
        
        const res = await req.body.json();
        if (res.error_code) {
            const uploadError = new Error(`Upload failed! Error Code #${res.error_code}`);
            uploadError.data = res;
            throw uploadError;
        }
        return res;
    }
    
    /**
     * Creates a new directory in the remote file system
     * @param {string} remoteDir - The path of the directory to create
     * @returns {Promise<Object>} The create directory response JSON
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async createDir(remoteDir){
        const formData = new this.FormUrlEncoded();
        formData.append('path', remoteDir);
        formData.append('isdir', 1);
        formData.append('block_list', '[]');
        
        const url = new URL(this.params.whost + '/api/create?a=commit');
        
        try{
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            // rdata.errno: -7 - param  path file name is invalid
            return rdata;
        }
        catch (error) {
            throw new Error('createFolder', { cause: error });
        }
    }
    
    /**
     * Creates a new file entry on the server after uploading chunks
     * @param {Object} data - File data including remote_dir, file, size, hash, upload_id, and chunks
     * @param {string} data.remote_dir - Remote directory path
     * @param {string} data.file - Filename
     * @param {number} data.size - File size in bytes
     * @param {Object} data.hash - Hash information
     * @param {string} data.hash.file - MD5 hash of full file
     * @param {string} data.hash.slice - MD5 hash of first slice
     * @param {number} data.hash.crc32 - CRC32 value
     * @param {Array<string>} data.hash.chunks - Array of MD5 chunk hashes
     * @param {string} data.upload_id - Upload ID obtained from precreate
     * @returns {Promise<Object>} The create file response JSON (includes MD5 and ETag)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async createFile(data){
        const formData = new this.FormUrlEncoded();
        formData.append('path', makeRemoteFPath(data.remote_dir, data.file));
        // formData.append('isdir', 0);
        formData.append('size', data.size);
        formData.append('isdir', 0);
        
        // check if has correct md5 values
        if(this.CheckMd5Val(data.hash.slice) && this.CheckMd5Val(data.hash.file)){
            formData.append('content-md5', data.hash.file);
            formData.append('slice-md5', data.hash.slice);
        }
        
        // check crc32int and ignore field for crc32 out of range
        if(Number.isSafeInteger(data.hash.crc32) && data.hash.crc32 >= 0 && data.hash.crc32 <= 0xFFFFFFFF){
            formData.append('content-crc32', data.hash.crc32);
        }
        
        formData.append('block_list', JSON.stringify(data.hash.chunks));;
        formData.append('uploadid', data.upload_id);
        formData.append('rtype', 2);
        
        // formData.append('local_ctime', '');
        // formData.append('local_mtime', '');
        // formData.append('zip_quality', '');
        // formData.append('zip_sign', '');
        // formData.append('is_revision', 0);
        // formData.append('mode', 2); // 2 is Batch Upload
        // formData.append('exif_info', exifJsonStr);
        
        const url = new URL(this.params.whost + '/api/create');
        
        try{
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            // rdata.errno: 31355 - pcs service failed
            if(rdata.md5){
                // encrypted etag
                rdata.emd5 = rdata.md5;
                // decrypted etag (without chunk count)
                rdata.md5 = this.DecodeMd5(rdata.emd5);
                // set custom etag
                rdata.etag = rdata.md5;
                if(data.hash.chunks.length > 1){
                    rdata.etag += '-' + data.hash.chunks.length;
                }
            }
            return rdata;
        }
        catch (error) {
            console.log(error);
            throw new Error('createFile', { cause: error });
        }
    }
    
    /**
     * Performs file management operations (delete, copy, move, rename)
     * @param {string} operation - Operation type: 'delete', 'copy', 'move', 'rename'
     * @param {Array} fmparams - Parameters for the operation (array of paths or objects)
     * @returns {Promise<Object>} The file manager response JSON
     * @async
     * @throws {Error} Throws error if fmparams is not an array, HTTP status is not 200, or request fails
     */
    async filemanager(operation, fmparams){
        // For Delete: ["/path1","path2.rar"]
        // For Move: [{"path":"/myfolder/source.bin","dest":"/target/","newname":"newfilename.bin"}]
        // For Copy same as move
        // + "ondup": newcopy, overwrite (optional, skip by default)
        // For rename [{"id":1111,"path":"/dir1/src.bin","newname":"myfile2.bin"}]
        
        // operation - copy (file copy), move (file movement), rename (file renaming), and delete (file deletion)
        // opera=copy: filelist: [{"path":"/hello/test.mp4","dest":"","newname":"test.mp4"}]
        // opera=move: filelist: [{"path":"/test.mp4","dest":"/test_dir","newname":"test.mp4"}]
        // opera=rename: filelist：[{"path":"/hello/test.mp4","newname":"test_one.mp4"}]
        // opera=delete: filelist: ["/test.mp4"]
        
        if(!Array.isArray(fmparams)){
            throw new Error('filemanager', { cause: new Error('FS paths should be in array!') });
        }
        
        const url = new URL(this.params.whost + '/api/filemanager');
        
        const formData = new this.FormUrlEncoded();
        formData.append('filelist', JSON.stringify(fmparams));
        
        try{
            if(this.data.jsToken === ''){
                await this.updateAppData();
            }
            
            url.search = new URLSearchParams({
                ...this.params.app,
                jsToken: this.data.jsToken,
                // 'async': 1,
                onnest: 'fail',
                opera: operation, // delete, copy, move, rename
            });
            
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            if(rdata.errno === 450016){
                await this.updateAppData();
                return await this.filemanager(operation, fmparams);
            }
            return rdata;
        }
        catch (error) {
            throw new Error('filemanager', { cause: error });
        }
    }
    
    /**
     * Retrieves a list of shares created by the user
     * @returns {Promise<Object>} The share list JSON (includes share entries)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async shareList(page = 1){
        const url = new URL(this.params.whost + '/share/teratransfer/sharelist');
        
        try{
            url.search = new URLSearchParams({
                // ...this.params.app,
                page_size: 100,
                page: page,
            });
            
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('shareList', { cause: error });
        }
    }
    
    /**
     * Sets sharing parameters (e.g., password, expiration) for specified files
     * @param {Array<string>} filelist - Array of file paths to share
     * @param {string} [pass=''] - Optional 4-character alphanumeric password
     * @param {number} [period=0] - Sharing period in days (0 for no expiration)
     * @returns {Promise<Object>} The share set response JSON (includes share IDs)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async shareSet(filelist, pass = '', period = 0){
        const url = new URL(this.params.whost + '/share/pset');
        
        try{
            url.search = new URLSearchParams({
                // ...this.params.app,
            });
            
            filelist = Array.isArray(filelist) ? filelist : [];
            filelist = JSON.stringify(filelist);
            
            pass = typeof pass === 'string' && pass.match(/^[0-9a-z]{4}$/i) ? pass : '';
            const schannel = pass !== '' ? 4 : 0;
            
            // 0 - infinity, otherwise valid X days
            period = parseInt(period);
            period = !isNaN(period) && Number.isSafeInteger(period) ? period : 0;
            
            const formData = new this.FormUrlEncoded();
            formData.append('schannel', schannel);
            formData.append('channel_list', '[]');
            formData.append('period', period);
            formData.append('path_list', filelist);
            formData.append('pwd', pass);
            
            const req = await request(url, {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                    Referer: this.params.whost,
                },
                body: formData.str(),
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('shareSet', { cause: error });
        }
    }
    
    /**
     * Cancels existing shares by share ID
     * @param {Array<number>} [shareid_list=[]] - Array of share IDs to cancel
     * @returns {Promise<Object>} The share cancel response JSON
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async shareCancel(shareid_list = []){
        const url = new URL(this.params.whost + '/share/cancel');
        
        try{
            url.search = new URLSearchParams({
                // ...this.params.app,
            });
            
            shareid_list = Array.isArray(shareid_list) ? shareid_list : [];
            shareid_list = JSON.stringify(shareid_list);
            
            const formData = new this.FormUrlEncoded();
            formData.append('shareid_list', shareid_list);
            
            const req = await request(url, {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                    Referer: this.params.whost,
                },
                body: formData.str(),
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('shareCancel', { cause: error });
        }
    }
    
    /**
     * Retrieves information for a shortened URL share
     * @param {string} shortUrl - The short url: after "surl="
     * @returns {Promise<Object>} The short URL info JSON (includes file list, permissions)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async shortUrlInfo(shortUrl){
        const url = new URL(this.params.whost + '/api/shorturlinfo');
        
        try{
            url.search = new URLSearchParams({
                //...this.params.app,
                shorturl: '1' + shortUrl,
                root: 1,
            });
            
            const connector = buildConnector({ ciphers: tls.DEFAULT_CIPHERS + ':!ECDHE-RSA-AES128-SHA' });
            const client = new Client(this.params.whost, { connect: connector });
            const req = await request(url, {
                method: 'GET',
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                dispatcher: client,
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('shortUrlInfo', { cause: error });
        }
    }
    
    /**
     * Lists files under a shortened URL share
     * @param {string} shortUrl - The short url: after "surl="
     * @param {string} [remoteDir=''] - Remote directory under share (empty for root)
     * @param {number} [page=1] - Page number for pagination
     * @returns {Promise<Object>} The short URL file list JSON (includes entries array)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async shortUrlList(shortUrl, remoteDir = '', page = 1){
        const url = new URL(this.params.whost + '/share/list');
        remoteDir = remoteDir || '';
        
        try{
            if(this.data.jsToken === ''){
                await this.updateAppData();
            }
            
            url.search = new URLSearchParams({
                ...this.params.app,
                jsToken: this.data.jsToken,
                shorturl: shortUrl,
                by: 'name',
                order: 'asc',
                num: 20000,
                dir: remoteDir,
                page: page,
            });
        
            if(remoteDir === ''){
                url.searchParams.append('root', '1');
            }
            
            const connector = buildConnector({ ciphers: tls.DEFAULT_CIPHERS + ':!ECDHE-RSA-AES128-SHA' });
            const client = new Client(this.params.whost, { connect: connector });
            const req = await request(url, {
                method: 'GET',
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                dispatcher: client,
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            // rdata.errno: 4000020 - need verify
            if(rdata.errno === 4000020){
                await this.updateAppData();
                return await this.shortUrlList(shortUrl, remoteDir, page);
            }
            return rdata;
        }
        catch (error) {
            throw new Error('shortUrlList', { cause: error });
        }
    }
    
    /**
     * Retrieves file difference (delta) information for synchronization
     * @returns {Promise<Object>} The file diff JSON (includes entries, request_id, has_more flag)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200, request fails, or on recursive errors
     */
    async fileDiff(){
        const formData = new this.FormUrlEncoded();
        formData.append('cursor', this.params.cursor);
        if(this.params.cursor === 'null'){
            formData.append('c', 'full');
        }
        formData.append('action', 'manual');
        
        const url = new URL(this.params.whost + '/api/filediff');
        url.search = new URLSearchParams({
            ...this.params.app,
            block_list: 1,
            // rand: '',
            // time: '',
            // vip: this.params.vip_type,
            // wp_retry_num: 2,
            // lang: this.params.lang,
            // logid: '',
        });
        
        try{
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            if(rdata.errno === 0){
                this.params.cursor = rdata.cursor;
                if(!Array.isArray(rdata.request_id)){
                    rdata.request_id = [ rdata.request_id ];
                }
                if(rdata.has_more){
                    // Extra FileDiff request...
                    const rFileDiff = await this.fileDiff();
                    if(rFileDiff.errno === 0){
                        rdata.reset = rFileDiff.reset;
                        rdata.request_id = rdata.request_id.concat(rFileDiff.request_id);
                        rdata.entries = Object.assign({}, rdata.entries, rFileDiff.entries);
                        rdata.has_more = rFileDiff.has_more;
                    }
                }
            }
            return rdata;
        }
        catch (error) {
            this.params.cursor = 'null';
            throw new Error('fileDiff', { cause: error });
        }
    }
    
    /**
     * Generates a PAN token for subsequent API requests
     * @returns {Promise<Object>} The PAN token response JSON (includes pan token and expire)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async genPanToken(){
        const url = new URL(this.params.whost + '/api/pantoken');
        
        try{
            url.search = new URLSearchParams({
                ...this.params.app,
                lang: this.params.lang,
                u: 'https://www.terabox.com',
            });
            
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('genPanToken', { cause: error });
        }
    }
    
    /**
     * Retrieves home page information (user info, sign data)
     * @returns {Promise<Object>} The home info JSON (includes sign1, sign3, data.signb)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async getHomeInfo(){
        const url = new URL(this.params.whost + '/api/home/info');
        
        try{
            const req = await request(url, {
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            if(rdata.errno === 0){
                rdata.data.signb = this.SignDownload(rdata.data.sign3, rdata.data.sign1);
            }
            return rdata;
        }
        catch (error) {
            throw new Error('getHomeInfo', { cause: error });
        }
    }
    
    /**
     * Initiates a download request for specified file IDs
     * @param {Array<number>} fs_ids - Array of file system IDs to download
     * @param {string} signb - Base64-encoded signature from getHomeInfo
     * @returns {Promise<Object>} The download response JSON (includes dlink URLs)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async download(fs_ids){
        const url = new URL(this.params.whost + '/api/download');
        
        try{
            const homeInfo = await this.getHomeInfo();
            if(homeInfo.errno !== 0){
                throw new Error('API error! Bad HomeInfo response');
            }
            
            const formData = new this.FormUrlEncoded({
                fidlist: JSON.stringify(fs_ids),
                type: 'dlink',
                vip: 2, // this.params.vip_type
                sign: homeInfo.data.signb,
                timestamp: homeInfo.data.timestamp,
                need_speed: 1, // Premium speed?..
            });
            
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('download', { cause: error });
        }
    }
    
    /**
     * Retrieves the streaming contents of a remote file
     * @param {string} remotePath - Remote video file
     * @param {string} type - Streaming type:
     *    <br>M3U8_FLV_264_480
     *    <br>M3U8_AUTO_240
     *    <br>M3U8_AUTO_360
     *    <br>M3U8_AUTO_480
     *    <br>M3U8_AUTO_720
     *    <br>M3U8_AUTO_1080
     *    <br>M3U8_SUBTITLE_SRT
     * @returns {Promise<Object>} m3u8 playlist, or JSON with error
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async getStream(remotePath = '/video.mp4', type = 'M3U8_AUTO_480'){
        const url = new URL(this.params.whost + '/api/streaming');
        
        try{
            const formData = new this.FormUrlEncoded();
            formData.append('path', remotePath);
            formData.append('type', type);
            formData.append('vip', 2);
            
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('getStream', { cause: error });
        }
    }
    
    /**
     * Retrieves metadata for specified remote files
     * @param {Array<Object>} remote_file_list - Array of file descriptor objects { fs_id, path, etc. }
     * @returns {Promise<Object>} The file metadata JSON (includes size, md5, etc.)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async getFileMeta(remote_file_list){
        const url = new URL(this.params.whost + '/api/filemetas');
        
        try{
            const formData = new this.FormUrlEncoded({
                dlink: 1,
                origin: 'dlna',
                target: JSON.stringify(remote_file_list),
            });
            
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('getFileMeta', { cause: error });
        }
    }
    
    /**
     * Retrieves a list of recent uploads for the account
     * @param {number} [page=1] - Page number for pagination
     * @returns {Promise<Object>} The recent uploads JSON (includes records array)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async getRecentUploads(page = 1){
        const url = new URL(this.params.whost + '/rest/recent/listall');
        
        try{
            url.search = new URLSearchParams({
                ...this.params.app,
                version:  this.params.ver_android,
                // num: 20000, ???
                // page: page, // ???
            });
            
            const req = await request(url, {
                method: 'GET',
                headers: {
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('getRecentUploads', { cause: error });
        }
    }
    
    /**
     * Queries transfer information for a shared URL
     * <br>
     * <br>Used to check if shared files can be transferred to the user's account
     * <br>before performing the actual transfer operation.
     *
     * @param {number} shareId - The share ID from shortUrlList response
     * @param {number} fromUk - The owner user ID (uk) from shortUrlList response
     * @returns {Promise<Object>} The query transfer response JSON
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async querySurlTransfer(shareId, fromUk){
        const url = new URL(this.params.whost + '/share/querysurltransfer');
        
        try{
            if(this.data.jsToken === ''){
                await this.updateAppData();
            }
            
            url.search = new URLSearchParams({
                ...this.params.app,
                jsToken: this.data.jsToken,
                'dp-logid': this.data.logid,
                bdstoken: this.data.bdstoken,
            });
            
            const formData = new this.FormUrlEncoded();
            formData.append('sid', shareId);
            formData.append('suk', fromUk);
            
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                    Referer: this.params.whost,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            return rdata;
        }
        catch (error) {
            throw new Error('querySurlTransfer', { cause: error });
        }
    }
    
    /**
     * Transfers (saves) shared files to the user's account
     * <br>
     * <br>This method saves files from a shared link to the user's own TeraBox storage.
     * <br>The files will be copied to the specified destination path.
     *
     * @param {number} shareId - The share ID of the shared content
     * @param {number} fromUk - The user ID (uk) of the share owner
     * @param {Array<number>} fsIds - Array of file system IDs to transfer
     * @param {string} [destPath='/'] - Destination path in user's storage
     * @param {Object} [options={}] - Optional parameters
     * @param {string} [options.ondup='newcopy'] - Duplicate handling strategy
     * @returns {Promise<Object>} The transfer response JSON (includes task_id on success)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async shareTransfer(shareId, fromUk, fsIds, destPath = '/', options = {}){
        const url = new URL(this.params.whost + '/share/transfer');
        
        try{
            if(this.data.jsToken === ''){
                await this.updateAppData();
            }
            
            url.search = new URLSearchParams({
                ...this.params.app,
                jsToken: this.data.jsToken,
                'dp-logid': this.data.logid,
                ondup: options.ondup || 'newcopy',
                async: 1,
                shareid: shareId,
                from: fromUk,
            });
            
            const formData = new this.FormUrlEncoded();
            formData.append('fsidlist', JSON.stringify(fsIds));
            formData.append('path', destPath);
            
            const req = await request(url, {
                method: 'POST',
                body: formData.str(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                    Referer: this.params.whost,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            // Handle verification errors by refreshing token and retrying
            if(rdata.errno === 400810){
                await this.updateAppData();
                return await this.shareTransfer(shareId, fromUk, fsIds, destPath, options);
            }
            return rdata;
        }
        catch (error) {
            throw new Error('shareTransfer', { cause: error });
        }
    }
    
    /**
     * Retrieves the RSA public key from the server for encryption
     * @returns {Promise<Object>} The public key response JSON (includes pp1 and pp2)
     * @async
     * @throws {Error} Throws error if HTTP status is not 200 or request fails
     */
    async getPublicKey(){
        const url = new URL(this.params.whost + '/passport/getpubkey');
        
        try{
            const req = await request(url, {
                method: 'GET',
                headers: {
                    'User-Agent': this.params.ua,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT),
            });
            
            if (req.statusCode !== 200) {
                throw new Error(`HTTP error! Status: ${req.statusCode}`);
            }
            
            const rdata = await req.body.json();
            
            if(rdata.code === 0){
                this.data.pubkey = this.DecryptAES(rdata.data.pp1, rdata.data.pp2);
            }
            
            return rdata;
        }
        catch (error) {
            throw new Error('getPublicKey', { cause: error });
        }
    }
}

// exports
export default TeraBoxApp;
export { TeraBoxApp };