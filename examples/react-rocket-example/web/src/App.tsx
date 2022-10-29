import {getAuth, GoogleAuthProvider, onAuthStateChanged, signInWithPopup, signOut} from "firebase/auth";
import {useEffect, useState} from "react";
import {initializeApp} from "firebase/app";

const firebaseConfig = {
    apiKey: import.meta.env.VITE_API_KEY,
    authDomain: import.meta.env.VITE_AUTH_DOMAIN,
    projectId: import.meta.env.VITE_PROJECT_ID,
    storageBucket: import.meta.env.VITE_STORAGE_BUCKET,
    messagingSenderId: import.meta.env.VITE_MESSAGING_SENDER_ID,
    appId: import.meta.env.VITE_APP_ID,
    measurementId: import.meta.env.VITE_MEASUREMENT_ID,
};

const firebaseApp = initializeApp(firebaseConfig);
const googleAuthProvider = new GoogleAuthProvider();

const useGoogleOAuth = () => async (): Promise<string | null> => {
    const auth = getAuth(firebaseApp);
    const authnedUser = await signInWithPopup(auth, googleAuthProvider);

    if (!authnedUser) return null

    const bearerToken = await authnedUser.user.getIdToken(true);
    return fetch(`${import.meta.env.VITE_BASE_URL}/verify`, {
        method: "GET",
        headers: {
            'Content-type': 'application/json',
            Authorization: `bearer ${bearerToken}`
        }
    })
        .then(resp => resp.json())
        .then(resp => resp.uid)
};

const App = () => {
    const googleOAuth = useGoogleOAuth();
    const [uid, setUid] = useState<string | null>(null)

    useEffect(() => {
        onAuthStateChanged(getAuth(firebaseApp), (authnedUser) => {
            if (authnedUser) {
                setUid(authnedUser.uid)
            }
        });
    });

    const handleSignIn = async () => {
        setUid(await googleOAuth())
    }

    const handleSignOut = async () => {
        const auth = getAuth(firebaseApp);
        await signOut(auth)
        setUid(null)
    }

    return <div style={{
        display: "flex",
        flexDirection: 'column',
        alignItems: "center"
    }}>
        <p>Current uid: {uid || "<no token>"}</p>
        <button type='button' onClick={() => handleSignIn()} style={{
            marginBottom: 20
        }}>
            Send a firebase token
        </button>
        <button type='button' onClick={() => handleSignOut()} disabled={!uid}>
            Delete your token in local state
        </button>
    </div>;
};

export default App;
