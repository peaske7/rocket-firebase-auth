import {getAuth, GoogleAuthProvider, onAuthStateChanged, signInWithPopup, signOut} from "firebase/auth";
import {useEffect, useState} from "react";
import {initializeApp} from "firebase/app";

// Set up the frontend firebase instance
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
// We'll be using google authentication in our example, but any authentication method (including custom tokens)
// should be supported by the backend
const googleAuthProvider = new GoogleAuthProvider();

const useGoogleOAuth = () => async (): Promise<string | null> => {
    const auth = getAuth(firebaseApp);
    const authnedUser = await signInWithPopup(auth, googleAuthProvider);

    // Early return if we fail to authenticate the user with firebase
    if (!authnedUser) return null

    // Get the authenticated user's firebase Id token that we'll use as our bearer token
    const bearerToken = await authnedUser.user.getIdToken(true);
    return fetch(`${import.meta.env.VITE_BASE_URL}/verify`, {
        method: "GET",
        headers: {
            // Make a GET request with the `Authorization` header set with our bearer token
            Authorization: `Bearer ${bearerToken}`
        }
    })
        .then(resp => resp.json())
        // We only want to return the decoded `uid` in our case
        .then(resp => resp.uid)
};

const App = () => {
    const googleOAuth = useGoogleOAuth();
    // The verified uid of the authenticated user
    const [uid, setUid] = useState<string | null>(null)

    useEffect(() => {
        // Set the local state for cases where a user is already authenticated
        onAuthStateChanged(getAuth(firebaseApp), (user) => {
            if (user) {
                setUid(user.uid)
            }
        });
    });

    const handleSignIn = async () => {
        // Set the local state to the verified user's uid
        setUid(await googleOAuth())
    }

    const handleSignOut = async () => {
        const auth = getAuth(firebaseApp);
        // Sign out of firebase
        await signOut(auth)
        // Set the local state back to it's initial state
        setUid(null)
    }

    return (
        <div style={{
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
        </div>
    );
};

export default App;
