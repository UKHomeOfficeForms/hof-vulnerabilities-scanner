export default async function fetchCompromisedPackages(URL) {
  try{
    const response = await fetch(URL);
    if (!response.ok) {
     console.warn(`Warning: Network error, status is : , ${response.status}, ${response.statusText}`);
    return null
    }
    return await response.text()
  } catch(error){
    // this will also appear when running the tests
    console.warn(`Warning: Failed to fetch compromised packages: ${error.message}`)
    return null
  };
}

