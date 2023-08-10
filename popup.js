document.getElementById('checkButton').addEventListener('click', async () => {
  const fileInput = document.getElementById('fileInput');
  const file = fileInput.files[0];

  if (!file) {
    alert('Please select a file.');
    return;
  }

  const apiKey = 'YOUR API KEY';
  const url = `https://www.virustotal.com/api/v3/files/${file.name}`;

  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'x-apikey': apiKey,
      },
    });

    if (!response.ok) {
      throw new Error('Network response was not ok.');
    }

    const data = await response.json();
    const result = JSON.stringify(data, null, 2);

    // Afficher les résultats dans la div "result"
    const resultDiv = document.getElementById('result');
    resultDiv.innerHTML = `<pre>${result}</pre>`;
  } catch (error) {
    console.error('Error:', error);
  }
});
