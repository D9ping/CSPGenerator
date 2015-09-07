"use strict";

var xmlhttp = new XMLHttpRequest();
xmlhttp.onreadystatechange = function() {
    if (xmlhttp.readyState === 4 && xmlhttp.status === 200) {
        var xmldoc = xmlhttp.responseXML;
        document.getElementById("result").textContent = xmldoc.getElementsByTagName("response")[0].textContent;
    }
};

xmlhttp.open('GET', '?getresponse=1', true);
xmlhttp.send();