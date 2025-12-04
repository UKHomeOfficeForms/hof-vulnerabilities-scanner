export default async function fetchCompromisedPackages(URL) {
  try{
    const response = await fetch(URL);
    if (!response.ok) {
      throw new Error(`Network response was not ok. Status is : , ${response.status}, ${response.statusText}`);
    }
    const data = await response.text()
    return data;
  } catch(error){
    throw new Error(`Failed to fetch compromised packages: ${error.message}`)
  };
}

