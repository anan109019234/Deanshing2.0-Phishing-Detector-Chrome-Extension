document.addEventListener('DOMContentLoaded', () => {
    const urlDisplay = document.getElementById('urlDisplay'); // Untuk menampilkan URL tab aktif
    const urlInput = document.getElementById('urlInput');     // KOLOM INPUT BARU
    const checkButton = document.getElementById('checkButton');
    const resultDiv = document.getElementById('result');
    const probabilitiesDiv = document.getElementById('probabilities');
    const errorMsgDiv = document.getElementById('errorMsg');

    // Fungsi pembantu untuk memvalidasi apakah string adalah URL yang terlihat
    function isValidUrl(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }

    // Dapatkan URL tab aktif saat popup dibuka dan isi ke urlDisplay dan urlInput
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs && tabs.length > 0 && tabs[0].url) {
            const currentUrl = tabs[0].url;
            urlDisplay.textContent = currentUrl;
            urlInput.value = currentUrl; // Isi kolom input dengan URL tab aktif
        } else {
            urlDisplay.textContent = 'Tidak ada URL tab aktif.';
            urlInput.value = ''; // Kosongkan input jika tidak ada URL tab
            urlInput.placeholder = 'Masukkan URL secara manual';
        }
    });

    // Event listener untuk tombol "Check URL"
    checkButton.addEventListener('click', () => {
        // Ambil URL dari kolom input
        const urlToCheck = urlInput.value.trim();

        // Validasi dasar URL
        if (!urlToCheck) {
            errorMsgDiv.textContent = 'Silakan masukkan URL untuk diperiksa.';
            return;
        }
        if (!isValidUrl(urlToCheck)) {
            errorMsgDiv.textContent = 'URL yang dimasukkan tidak valid.';
            return;
        }

        // Tampilkan status "Checking..."
        resultDiv.className = 'loading';
        resultDiv.textContent = 'Checking...';
        probabilitiesDiv.textContent = ''; // Kosongkan probabilitas sebelumnya
        errorMsgDiv.textContent = ''; // Kosongkan pesan error sebelumnya
        checkButton.disabled = true; // Nonaktifkan tombol saat pemeriksaan berlangsung

        // Kirim pesan ke background script untuk melakukan prediksi
        chrome.runtime.sendMessage({ action: "predictPhishing", url: urlToCheck }, (response) => {
            checkButton.disabled = false; // Aktifkan kembali tombol setelah pemeriksaan selesai

            // Tangani error jika background script tidak merespons
            if (chrome.runtime.lastError) {
                console.error("Runtime error:", chrome.runtime.lastError);
                resultDiv.className = 'error';
                resultDiv.textContent = 'Error: Gagal terhubung ke layanan deteksi.';
                errorMsgDiv.textContent = 'Pastikan server backend berjalan.';
                return;
            }

            // Tampilkan hasil prediksi
            if (response.status === "success") {
                resultDiv.textContent = `Result: ${response.prediction}`;
                if (response.prediction === "Legitimate") {
                    resultDiv.className = 'legitimate'; // Tambahkan kelas CSS untuk styling hijau
                } else if (response.prediction === "Phishing") {
                    resultDiv.className = 'phishing';   // Tambahkan kelas CSS untuk styling merah
                } else {
                    resultDiv.className = 'unknown';    // Kelas default jika hasil tidak dikenali
                }
                probabilitiesDiv.textContent = `Legitimate: ${(response.probability_legitimate * 100).toFixed(2)}% | Phishing: ${(response.probability_phishing * 100).toFixed(2)}%`;
            } else {
                resultDiv.className = 'error';
                resultDiv.textContent = `Error: ${response.message}`;
                errorMsgDiv.textContent = response.message;
                console.error("Backend error response:", response.message);
            }
        });
    });
});