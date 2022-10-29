/// <reference types="vite/client" />

interface ImportMetaEnv {
    VITE_BASE_URL: Readonly<string>;
    VITE_API_KEY: Readonly<string>;
    VITE_AUTH_DOMAIN: Readonly<string>;
    VITE_PROJECT_ID: Readonly<string>;
    VITE_STORAGE_BUCKET: Readonly<string>;
    VITE_MESSAGING_SENDER_ID: Readonly<string>;
    VITE_APP_ID: Readonly<string>;
}

interface ImportMeta {
    readonly env: ImportMetaEnv;
}
