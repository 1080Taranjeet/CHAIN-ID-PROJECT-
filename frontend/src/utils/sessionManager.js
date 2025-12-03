export const setSessionWithExpiry = (key, value, ttlInDays = 7) => {
  const now = new Date();
  const expiry = now.getTime() + ttlInDays * 24 * 60 * 60 * 1000;
  // alert(value.deviceId + " and the sessionID " + value.sessionId + " set with expiry of " + ttlInDays + " days");
  const sessionObject = {
    value,
    expiry,
  };

  localStorage.setItem(key, JSON.stringify(sessionObject));
  // alert(key + " set with expiry of " + ttlInDays + " days");
};

export const getSessionWithExpiry = (key) => {
  const itemStr = localStorage.getItem(key);
  if (!itemStr) return null;

  try {
    const item = JSON.parse(itemStr);
    const now = new Date().getTime();

    if (now > item.expiry) {
      localStorage.removeItem(key);
      return null;
    }

    return item.value;
  } catch (err) {
    console.error('Failed to parse session item:', err);
    return null;
  }
};

// ✅ Add this function 👇
export const clearSession = (key) => {
  localStorage.removeItem(key);
};
