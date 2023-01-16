document.getElementById("ttd").addEventListener('click', function() 
    {
        document.getElementById("formb").style.display = "none";
        document.getElementById("post_uploadb").style.display = "none";
        document.getElementById("preview").style.display = "none";
        document.getElementById("forma").style.display = "";
        document.getElementById("status").innerHTML = "";
        fetch('https://ipinfo.io/json')
            .then(response => response.json())
            .then(data => document.getElementById("region").value = data.region);
    });

document.getElementById("check").addEventListener('click', function() 
    {
        document.getElementById("forma").style.display = "none";
        document.getElementById("post_uploada").style.display = "none";
        document.getElementById("preview").style.display = "none";
        document.getElementById("formb").style.display = "";
        document.getElementById("status").innerHTML = "";
    });

document.getElementById("file").addEventListener('change', function() {
    pdfjsLib.getDocument(URL.createObjectURL($("#file").get(0).files[0])).promise.then(function(doc){
        if (doc.numPages < document.getElementById("page").value || [null, undefined, ""].includes(document.getElementById("page").value)) {
        window.alert("The page to be sealed does not exist on the PDF.");
        } else if (document.getElementById("file").files[0].name.slice(-3).toUpperCase() != "PDF") {
        window.alert("The files you have uploaded are not PDFs. Please try again.");
        } else {
            loadCanvas(URL.createObjectURL($("#file").get(0).files[0]));
        }
    });
})

document.getElementById("filecheck").addEventListener('change', function() {
    document.getElementById("post_uploadb").style.display = "";
})

var rect = {};
var drag = false;
var c;
var ctx;
var src;
var vh;
function loadCanvas(fileuri) {
    console.log(fileuri);
    c = document.getElementById("pgCanvas");
    document.getElementById("post_uploada").style.display = "";
    ctx = c.getContext("2d");
    pdfjsLib.getDocument({url: fileuri}).promise.then(function(doc) {
        doc.getPage(parseInt(document.getElementById("page").value)).then(function(page) {
            var viewport = page.getViewport({scale: 1});
            vh = viewport.height;
            c.height = vh;
            c.width = viewport.width;
            var renderContext = {
            canvasContext: ctx,
            viewport: viewport
            };
            page.render(renderContext).promise.then(() => {
                    src = c.toDataURL();
                });
            });
        });
    c.addEventListener('mousedown', mouseDown, false);
    c.addEventListener('mouseup', mouseUp, false);
    c.addEventListener('mousemove', mouseMove, false);
};

function mouseDown(e) {
rect.x1 = e.pageX - this.offsetLeft;
rect.y1 = e.pageY - this.offsetTop;
drag = true;
}

function mouseUp() { drag = false; }

function mouseMove(e) {
if (drag) {
    ctx.clearRect(0, 0, 500, 500);
    var img;
    img = new Image();
    img.src = src; 
    ctx.drawImage(img, 0, 0, img.width,    img.height, 0, 0, c.width, c.height);
    rect.w = (e.pageX - this.offsetLeft) - rect.x1;
    rect.x2 = e.pageX - this.offsetLeft;
    rect.h = (e.pageY - this.offsetTop) - rect.y1;
    rect.y2 = e.pageY - this.offsetTop
    ctx.strokeStyle = 'red';
    ctx.strokeRect(rect.x1, rect.y1, rect.w, rect.h);
    }
}

document.getElementById("area").addEventListener("click", function(e) {
    e.target.disabled= true;
    e.target.innerHTML="Selected!";
    document.getElementById("submit1").disabled=false;
    var min_side = Math.min(rect.w, rect.h); //square-ifying the seal area
    document.getElementById("ycom").value = vh;
    rect.w = min_side; rect.h = min_side;
    rect.x2 = rect.x1 + rect.w;
    rect.y2 = rect.y1 + rect.h;
    console.log(rect);
    var coords = ["x1", "x2", "y1", "y2"];
    for (var i of coords) {
        document.getElementById(i).value=rect[i];
    }
})

document.getElementById("formdata").addEventListener("submit", function(e) {
    document.getElementById("submit1").disabled=true;
    e.target.submit();
})

document.getElementById("formdatab").addEventListener("submit", function(e) {
    document.getElementById("submit2").disabled=true;
    e.target.submit();
})
