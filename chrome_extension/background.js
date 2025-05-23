// background.js atau service-worker.js

// Konstanta untuk awalan ID notifikasi
const NOTIFICATION_ID_PREFIX = "deanshing_url_check_";

// Fungsi untuk memeriksa URL dengan backend Flask
async function predictPhishing(url) {
    try {
        const response = await fetch('http://127.0.0.1:5000/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        });
        const data = await response.json();
        return data; // Backend diharapkan mengembalikan { prediction, probability_legitimate, probability_phishing, reasons (opsional) }
    } catch (error) {
        console.error('Error connecting to Flask backend:', error);
        return { status: "error", message: "Failed to connect to backend. Is the Flask server running?" };
    }
}

// Fungsi pembantu untuk memvalidasi apakah string adalah URL yang terlihat
function isValidUrl(string) {
    let tempString = string.trim();
    if (!tempString) return false;

    const urlPattern = new RegExp(
        '^(https?:\\/\\/)?' + // opsional: protokol http atau https
        '((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.)+[a-z]{2,})' + // nama domain (misal: example.com, my.website.co.id)
        '(\\:\\d+)?' + // opsional: port number
        '(\\/[-a-z\\d%_.~+]*)*' + // opsional: path
        '(\\?[;&a-z\\d%_.~+=-]*)?' + // opsional: query string
        '(\\#[-a-z\\d_]*)?$', 'i' // opsional: fragment
    );

    if (urlPattern.test(tempString)) {
        let testString = tempString;
        if (!testString.startsWith("http://") && !testString.startsWith("https://")) {
            testString = "http://" + testString;
        }
        try {
            const url = new URL(testString);
            if (url.protocol === 'chrome:' || url.protocol === 'chrome-extension:') {
                return false;
            }
            if (url.hostname.split('.').length < 2 && url.hostname.length < 5) {
                return false;
            }
            return true;
        } catch (e) {
            return false;
        }
    }

    return false;
}

// Fungsi untuk menampilkan notifikasi Chrome
// Sekarang menerima URL yang relevan untuk notifikasi yang bisa diklik
function showNotification(title, message, clickableUrl = null) {
    let notificationId = ''; // Default: notifikasi tidak bisa diklik

    // Tambahkan teks "klik untuk lanjut ke situs" dan buat ID notifikasi unik
    let finalMessage = message;
    if (clickableUrl) {
        finalMessage += "\n\n(klik untuk lanjut ke situs)";
        // Buat ID unik dengan menambahkan URL yang diperiksa ke prefix
        // Gunakan encodeURIComponent untuk menangani karakter khusus di URL
        notificationId = NOTIFICATION_ID_PREFIX + encodeURIComponent(clickableUrl);
    }

    chrome.notifications.create(notificationId, {
        type: 'basic',
        iconUrl: 'icons/logo.png',
        title: title,
        message: finalMessage,
        priority: 2
    });
}

// 1. Buat item menu konteks (klik kanan) saat ekstensi diinstal atau diperbarui
chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: "checkPhishingSelection",
        title: "Periksa URL ini",
        contexts: ["selection", "link"]
    });
    console.log("Context menu item 'Periksa URL ini' created/updated.");
});

// 2. Dengarkan klik pada item menu konteks
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    if (info.menuItemId === "checkPhishingSelection") {
        let urlToCheck = "";

        if (info.linkUrl) {
            urlToCheck = info.linkUrl;
            console.log("Context menu clicked on a link. URL:", urlToCheck);
        } else if (info.selectionText) {
            urlToCheck = info.selectionText;
            console.log("Context menu clicked on selected text. Text:", urlToCheck);
        } else {
            // Notifikasi ini tidak perlu bisa diklik ke URL manapun
            showNotification("Deanshing 2.0", "Tidak ada URL atau teks yang relevan.");
            return;
        }

        if (!urlToCheck) {
            // Notifikasi ini tidak perlu bisa diklik ke URL manapun
            showNotification("Deanshing 2.0", "Tidak ada URL atau teks yang ditemukan untuk diperiksa.");
            return;
        }

        if (isValidUrl(urlToCheck)) {
            showNotification("Deanshing 2.0", `Sedang memeriksa URL: ${urlToCheck.substring(0, 50)}...`);

            const result = await predictPhishing(urlToCheck);

            if (result && result.status === "success") {
                let title = "Deanshing 2.0 Result";
                let message = `URL ini: ${result.prediction}`;
                let reasonsMessage = "";

                if (result.prediction === "Phishing") {
                    title = "🚨 POTENSI PHISHING TERDETEKS! 🚨";
                    message += ` (L: ${(result.probability_legitimate * 100).toFixed(0)}%, P: ${(result.probability_phishing * 100).toFixed(0)}%).`;

                    if (result.reasons && Array.isArray(result.reasons) && result.reasons.length > 0) {
                        reasonsMessage = "\nAlasan: " + result.reasons.join(", ");
                    } else if (result.reason_details && typeof result.reason_details === 'string') {
                        reasonsMessage = "\nAlasan: " + result.reason_details;
                    }
                    message += reasonsMessage;
                } else { // Legitimate
                    title = "✅ URL Aman!";
                    message += ` (L: ${(result.probability_legitimate * 100).toFixed(0)}%, P: ${(result.probability_phishing * 100).toFixed(0)}%).`;
                }

                // Tambahkan pesan "klik untuk lanjut ke situs" dan berikan URL yang diperiksa
                // Notifikasi ini akan bisa diklik untuk membuka URL yang baru diperiksa
                showNotification(title, message, urlToCheck); // <-- urlToCheck dikirim sebagai argumen
            } else {
                // Notifikasi error ini tidak perlu bisa diklik ke URL manapun
                showNotification("Deanshing 2.0 Error", result ? result.message : "Gagal terhubung ke backend.");
            }
        } else {
            // Notifikasi 'bukan URL' ini tidak perlu bisa diklik ke URL manapun
            showNotification("Deanshing 2.0", "Teks yang dipilih bukan URL yang valid.");
        }
    }
});

// --- Event Listener untuk Notifikasi yang Diklik ---
chrome.notifications.onClicked.addListener((notificationId) => {
    // Periksa apakah ID notifikasi dimulai dengan prefix kita
    if (notificationId.startsWith(NOTIFICATION_ID_PREFIX)) {
        // Ekstrak URL dari ID notifikasi
        const clickedUrl = decodeURIComponent(notificationId.substring(NOTIFICATION_ID_PREFIX.length));

        console.log(`Notifikasi untuk URL: ${clickedUrl} diklik. Membuka situs...`);
        chrome.tabs.create({ url: clickedUrl }); // Buka tab baru dengan URL yang diperiksa
    }
});

// Listener untuk pesan dari popup.js (pertahankan ini agar popup manual tetap berfungsi)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "predictPhishing") {
        predictPhishing(request.url).then(response => {
            sendResponse(response);
        });
        return true; // Indicates an asynchronous response
    }
});