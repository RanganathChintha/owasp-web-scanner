function startScan() {
    const url = document.getElementById("url").value;
    const jwt = document.getElementById("jwt").value;
    const log = document.getElementById("log");

    log.innerHTML = "";

    const evt = new EventSource(`/scan?url=${url}&jwt=${jwt}`);

    evt.onmessage = function(e) {
        log.innerHTML += e.data + "<br>";
        log.scrollTop = log.scrollHeight;
    };

    evt.onerror = function() {
        evt.close();
    };
}
