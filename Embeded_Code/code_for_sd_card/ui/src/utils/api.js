export const fetchRequest = async ({ src, method, payload }) => {
  return fetch(`${window.location.origin}${src}`, {
    method,
    headers: {
      "Content-Type": "json/application",
    },
    body: method === "POST" ? JSON.stringify({ ...payload }) : undefined,
  })
    .then((response) => {
      if (!response.ok) {
        console.info(`[${src}] - ${method} - FAIL: ${response.text()}`);
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return response.json();
    })
    .then((response) => {
      console.info(`[${src}] - ${method} - SUCCESS: `, response);
      return response;
    });
};
