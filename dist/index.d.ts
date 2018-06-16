export declare const decode: (stringData: string, secret: string) => Promise<string>;
export declare const encode: (stringData: string, secret: string) => Promise<string>;
export declare const decodeSync: (encryptedStringData: string, secret: string) => string;
export declare const encodeSync: (stringData: string, secret: string) => string;
