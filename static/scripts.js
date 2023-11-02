$("#scanForm").submit(function (e) {
    e.preventDefault();
    const target = $("#target").val();
    const startPort = $("#startPort").val();
    const endPort = $("#endPort").val();
    $("#loading").show();
    
    $.post("/scan", { target, startPort, endPort }, function (data) {
        const tableBody = $("#resultsTable tbody");
        tableBody.empty();
        
        data.open_ports_details.forEach(detail => {
            const serviceInfo = detail.service || "Unknown";
            tableBody.append(
                `<tr>
                    <td>${detail.port}/tcp</td>
                    <td>${detail.state}</td>
                    <td>${serviceInfo}</td>
                </tr>`
            );
        });

        // Update OS guess
        $("#osGuess").text("Operating System : " + data.os_guess);
        $("#resultsTable").show();
        $("#loading").hide();
    });
});


