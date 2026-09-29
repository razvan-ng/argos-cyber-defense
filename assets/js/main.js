/* Argos Cyber Defense · Landing page
   Sense dependències externes ni galetes. */

// S'executa abans de pintar la pàgina: activa els estils que depenen de JavaScript
document.documentElement.classList.add("js");

document.addEventListener("DOMContentLoaded", function () {
  initHeader();
  initMobileNav();
  initActiveSection();
  initReveal();
  initTeamPhotos();
  initRepoLinks();
  initCopyButtons();
  initAuditForm();
});

/* Capçalera: canvia d'aspecte quan es fa scroll */
function initHeader() {
  var header = document.getElementById("capcalera");
  if (!header) return;
  var update = function () {
    header.classList.toggle("is-scrolled", window.scrollY > 12);
  };
  update();
  window.addEventListener("scroll", update, { passive: true });
}

/* Menú desplegable en pantalles petites */
function initMobileNav() {
  var toggle = document.querySelector(".nav-toggle");
  var nav = document.getElementById("menu-principal");
  if (!toggle || !nav) return;

  var setOpen = function (open) {
    toggle.setAttribute("aria-expanded", String(open));
    nav.classList.toggle("is-open", open);
  };

  toggle.addEventListener("click", function () {
    setOpen(toggle.getAttribute("aria-expanded") !== "true");
  });
  nav.addEventListener("click", function (e) {
    if (e.target.closest("a")) setOpen(false);
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") setOpen(false);
  });
}

/* Marca l'enllaç del menú corresponent a la secció visible */
function initActiveSection() {
  if (!("IntersectionObserver" in window)) return;
  var links = document.querySelectorAll('.site-nav ul a[href^="#"]');
  var byId = {};
  links.forEach(function (a) { byId[a.getAttribute("href").slice(1)] = a; });

  var observer = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (!entry.isIntersecting) return;
      links.forEach(function (a) { a.classList.remove("is-active"); });
      var link = byId[entry.target.id];
      if (link) link.classList.add("is-active");
    });
  }, { rootMargin: "-45% 0px -50% 0px" });

  document.querySelectorAll("main section[id]").forEach(function (s) { observer.observe(s); });
}

/* Aparició suau dels blocs en fer scroll */
function initReveal() {
  var items = document.querySelectorAll(".reveal");
  if (!("IntersectionObserver" in window)) {
    items.forEach(function (el) { el.classList.add("is-visible"); });
    return;
  }
  var observer = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) {
        entry.target.classList.add("is-visible");
        observer.unobserve(entry.target);
      }
    });
  }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
  items.forEach(function (el) { observer.observe(el); });
}

/* Fotografies de l'equip.
   Cada imatge es busca a assets/img/equip/ amb el nom indicat a data-photo
   i s'accepten diverses extensions. Si no n'hi ha cap, es mostren les inicials. */
var PHOTO_EXTENSIONS = [".jpg", ".jpeg", ".png", ".webp", ".JPG", ".JPEG", ".PNG"];

function initTeamPhotos() {
  document.querySelectorAll("img[data-photo]").forEach(function (img) {
    var base = img.getAttribute("data-photo");
    var figure = img.closest(".member__photo");

    // Mentre es busca la fotografia es mostren les inicials
    if (figure) figure.classList.add("is-empty");
    img.removeAttribute("src");

    var probe = function (index) {
      if (index >= PHOTO_EXTENSIONS.length) return; // cap fotografia: es queden les inicials
      var url = base + PHOTO_EXTENSIONS[index];
      var test = new Image();
      test.onload = function () {
        img.src = url;
        if (figure) figure.classList.remove("is-empty");
      };
      test.onerror = function () { probe(index + 1); };
      test.src = url;
    };
    probe(0);
  });
}

/* Enllaços al repositori de GitHub.
   Quan la web està publicada a https://USUARI.github.io/REPOSITORI/,
   es dedueix automàticament l'adreça https://github.com/USUARI/REPOSITORI. */
function initRepoLinks() {
  var repoUrl = getRepoUrl();

  document.querySelectorAll("[data-repo-path]").forEach(function (a) {
    if (!repoUrl) return;
    var path = a.getAttribute("data-repo-path");
    a.href = path ? repoUrl + "/" + path : repoUrl;
    a.rel = "noopener";
  });

  document.querySelectorAll("[data-repo-only]").forEach(function (el) {
    if (repoUrl) el.hidden = false;
    else el.remove();
  });
}

function getRepoUrl() {
  var host = window.location.hostname.toLowerCase();
  var suffix = ".github.io";
  if (host.slice(-suffix.length) !== suffix) return null;

  var user = host.slice(0, -suffix.length);
  var firstSegment = window.location.pathname.split("/").filter(Boolean)[0];
  // Web de projecte: /REPOSITORI/...  ·  Web d'usuari: el repositori es diu USUARI.github.io
  var repo = firstSegment && !/\.[a-z0-9]+$/i.test(firstSegment) ? firstSegment : host;
  return "https://github.com/" + user + "/" + repo;
}

/* Botó per copiar les ordres d'instal·lació */
function initCopyButtons() {
  document.querySelectorAll("[data-copy-target]").forEach(function (btn) {
    var label = btn.querySelector("span");
    btn.addEventListener("click", function () {
      var target = document.getElementById(btn.getAttribute("data-copy-target"));
      if (!target) return;
      copyText(target.innerText.trim()).then(function () {
        btn.classList.add("is-copied");
        if (label) label.textContent = "Copiat!";
        setTimeout(function () {
          btn.classList.remove("is-copied");
          if (label) label.textContent = "Copia";
        }, 1800);
      });
    });
  });
}

/* Formulari de sol·licitud d'auditoria.
   S'obre com a finestra modal des de qualsevol botó amb data-open-form i s'envia
   per AJAX a FormSubmit, que fa arribar les respostes per correu electrònic.
   Sense JavaScript, els botons continuen funcionant com a enllaços normals. */
function initAuditForm() {
  var dialog = document.getElementById("formulari-auditoria");
  var form = document.getElementById("form-auditoria");
  if (!dialog || !form || typeof dialog.showModal !== "function") return;

  var done = dialog.querySelector(".form-done");
  var status = form.querySelector(".form-status");
  var submitBtn = form.querySelector('button[type="submit"]');
  var submitLabel = submitBtn.querySelector("span");
  var contactEmail = form.getAttribute("data-contact");

  var setStatus = function (text, isError) {
    status.textContent = text || "";
    status.classList.toggle("is-error", !!isError);
  };

  var reset = function () {
    form.hidden = false;
    done.hidden = true;
    setStatus("");
  };

  var open = function () {
    if (!done.hidden) { form.reset(); reset(); }
    dialog.showModal();
    document.documentElement.classList.add("modal-open");
  };

  var close = function () { dialog.close(); };

  document.querySelectorAll("[data-open-form]").forEach(function (el) {
    el.addEventListener("click", function (e) {
      e.preventDefault();
      open();
    });
  });
  dialog.querySelectorAll("[data-close-form]").forEach(function (el) {
    el.addEventListener("click", close);
  });
  // Clic fora del panell (sobre el fons fosc) per tancar
  dialog.addEventListener("click", function (e) {
    if (e.target === dialog) close();
  });
  dialog.addEventListener("close", function () {
    document.documentElement.classList.remove("modal-open");
  });

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var data = {};
    new FormData(form).forEach(function (value, key) { data[key] = value; });
    if (data._honey) return; // camp parany omplert: probablement un robot

    submitBtn.disabled = true;
    submitLabel.textContent = "Enviant...";
    setStatus("");

    var endpoint = form.action.replace("formsubmit.co/", "formsubmit.co/ajax/");
    fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(data)
    })
      .then(function (response) { return response.json(); })
      .then(function (result) {
        if (result.success === true || result.success === "true") {
          dialog.querySelector(".form-done__email").textContent = data.email;
          form.hidden = true;
          done.hidden = false;
          form.reset();
        } else {
          showSendError(result.message);
        }
      })
      .catch(function () { showSendError(); })
      .then(function () {
        submitBtn.disabled = false;
        submitLabel.textContent = "Envia la sol·licitud";
      });
  });

  function showSendError(detail) {
    setStatus("", true);
    status.appendChild(document.createTextNode(
      "No s'ha pogut enviar la sol·licitud" + (detail ? " (" + detail + ")" : "") + ". Torneu-ho a provar o escriviu-nos a "
    ));
    var link = document.createElement("a");
    link.href = "mailto:" + contactEmail;
    link.textContent = contactEmail;
    status.appendChild(link);
    status.appendChild(document.createTextNode("."));
  }
}

function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  return new Promise(function (resolve) {
    var area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.className = "visually-hidden";
    document.body.appendChild(area);
    area.select();
    try { document.execCommand("copy"); } catch (e) { /* sense suport */ }
    document.body.removeChild(area);
    resolve();
  });
}
