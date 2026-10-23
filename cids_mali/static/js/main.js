document.addEventListener('DOMContentLoaded', () => {
  const root = document.documentElement;
  const body = document.body;
  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const initTheme = () => {
    const savedTheme = localStorage.getItem('cids-theme');
    if (savedTheme === 'dark') {
      body.setAttribute('data-theme', 'dark');
    }
  };

  const updateThemeButton = () => {
    const isDark = body.getAttribute('data-theme') === 'dark';
    document.querySelectorAll('.theme-toggle').forEach((toggle) => {
      const icon = toggle.querySelector('.theme-toggle__icon');
      icon?.setAttribute('data-lucide', isDark ? 'moon' : 'sun');
      toggle.setAttribute('aria-label', isDark ? 'Basculer en thème clair' : 'Basculer le thème sombre');
      toggle.setAttribute('aria-pressed', String(isDark));
    });
    window.lucide?.createIcons();
  };

  const toggleTheme = () => {
    const current = body.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    const next = current === 'dark' ? 'light' : 'dark';
    body.setAttribute('data-theme', next);
    localStorage.setItem('cids-theme', next);
    updateThemeButton();
    document.dispatchEvent(new CustomEvent('cids-theme-change', { detail: { theme: next } }));
  };

  const themeButtons = document.querySelectorAll('.theme-toggle');
  themeButtons.forEach((button) => {
    button.addEventListener('click', toggleTheme);
  });

  document.querySelectorAll('form[data-confirm]').forEach((form) => {
    form.addEventListener('submit', (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });

  initTheme();
  window.lucide?.createIcons();
  updateThemeButton();

  if (!prefersReducedMotion) {
    const revealItems = document.querySelectorAll('.reveal-on-scroll');
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.14 });

    revealItems.forEach((el) => {
      el.classList.add('reveal-target');
      observer.observe(el);
    });
  } else {
    document.querySelectorAll('.reveal-on-scroll').forEach((el) => el.classList.add('is-visible'));
  }

  const animateCounter = (el) => {
    const target = Number(el.dataset.target || 0);
    const duration = 1200;
    const start = performance.now();
    const step = (now) => {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const value = Math.round(target * eased);
      el.textContent = value.toLocaleString('fr-FR');
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  };

  const counters = document.querySelectorAll('.stat-number');
  counters.forEach((counter) => {
    animateCounter(counter);
  });

  const navToggle = document.querySelector('.nav-toggle');
  const mainNav = document.querySelector('.main-nav');
  if (navToggle && mainNav) {
    navToggle.addEventListener('click', () => {
      const expanded = navToggle.getAttribute('aria-expanded') === 'true';
      navToggle.setAttribute('aria-expanded', String(!expanded));
      mainNav.classList.toggle('is-open');
    });
    navToggle.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        navToggle.setAttribute('aria-expanded', 'false');
        mainNav.classList.remove('is-open');
        navToggle.focus();
      }
    });
  }

  const classFilter = document.getElementById('class-filter');
  const studentRows = document.querySelectorAll('#students-list-body tr[data-class]');
  if (classFilter) {
    classFilter.addEventListener('change', () => {
      const selectedClass = classFilter.value;
      studentRows.forEach((row) => {
        row.hidden = selectedClass !== 'Toutes' && row.dataset.class !== selectedClass;
      });
    });
  }

  document.querySelectorAll('.table-sort').forEach((button) => {
    button.addEventListener('click', () => {
      const table = button.closest('table');
      const body = table?.querySelector('tbody');
      if (!body) return;
      const column = Number(button.dataset.sortIndex);
      const header = button.closest('th');
      const ascending = header.getAttribute('aria-sort') !== 'ascending';
      const rows = Array.from(body.querySelectorAll('tr'));
      rows.sort((left, right) => {
        const leftCell = left.cells[column];
        const rightCell = right.cells[column];
        const leftValue = leftCell?.dataset.sortValue || leftCell?.textContent.trim() || '';
        const rightValue = rightCell?.dataset.sortValue || rightCell?.textContent.trim() || '';
        return leftValue.localeCompare(rightValue, 'fr', { numeric: true }) * (ascending ? 1 : -1);
      });
      body.replaceChildren(...rows);
      table.querySelectorAll('th[aria-sort]').forEach((cell) => cell.setAttribute('aria-sort', 'none'));
      header.setAttribute('aria-sort', ascending ? 'ascending' : 'descending');
      const icon = button.querySelector('[data-lucide]');
      icon?.setAttribute('data-lucide', ascending ? 'arrow-up' : 'arrow-down');
      window.lucide?.createIcons();
    });
  });

  const issueForm = document.getElementById('issue-form');
  const steps = Array.from(document.querySelectorAll('.step'));
  const formSteps = Array.from(document.querySelectorAll('.form-step'));
  const progressBar = document.getElementById('issue-progress-bar');
  const nextBtn = document.querySelector('.btn-next');
  const backBtn = document.querySelector('.btn-back');
  const submitBtn = document.getElementById('issue-submit');
  let currentStep = 0;

  function updateFormStep() {
    formSteps.forEach((stepEl, index) => {
      stepEl.classList.toggle('is-active', index === currentStep);
    });
    steps.forEach((stepEl, index) => {
      stepEl.classList.toggle('is-active', index === currentStep);
    });
    const ratio = ((currentStep + 1) / formSteps.length) * 100;
    if (progressBar) progressBar.style.width = `${ratio}%`;
    backBtn.hidden = currentStep === 0;
    nextBtn.hidden = currentStep === formSteps.length - 1;
    submitBtn.style.display = currentStep === formSteps.length - 1 ? 'inline-flex' : 'none';
  }

  if (nextBtn && backBtn && formSteps.length) {
    nextBtn.addEventListener('click', () => {
      if (currentStep < formSteps.length - 1) {
        currentStep += 1;
        updateFormStep();
      }
    });

    backBtn.addEventListener('click', () => {
      if (currentStep > 0) {
        currentStep -= 1;
        updateFormStep();
      }
    });

    updateFormStep();
  }

  const photoInput = document.getElementById('photo');
  const photoPreview = document.getElementById('photo-preview');
  const dropzone = document.getElementById('photo-dropzone');
  const previewPhoto = document.getElementById('preview-photo');
  const previewName = document.getElementById('preview-name');
  const previewClass = document.getElementById('preview-class');
  const previewSchool = document.getElementById('preview-school');
  const previewCategory = document.getElementById('preview-category');
  const examCategory = document.getElementById('exam_category');
  const previewIssued = document.getElementById('preview-issued');
  const previewExpires = document.getElementById('preview-expires');

  const syncPreview = () => {
    const firstName = document.getElementById('first_name')?.value || 'Prénom';
    const lastName = document.getElementById('last_name')?.value || 'Nom';
    const studentClass = document.getElementById('student_class')?.value || 'Classe';
    const school = document.getElementById('school')?.value || 'Établissement';
    previewName.textContent = `${firstName} ${lastName}`.trim() || 'Nom complet';
    previewClass.textContent = studentClass || 'Classe';
    previewSchool.textContent = school || 'Établissement';
    if (previewCategory && examCategory) {
      previewCategory.textContent = examCategory.options[examCategory.selectedIndex]?.text || 'DEF';
    }
    const issued = new Date();
    const expires = new Date();
    expires.setFullYear(expires.getFullYear() + 1);
    previewIssued.textContent = issued.toLocaleDateString('fr-FR');
    previewExpires.textContent = expires.toLocaleDateString('fr-FR');
  };

  if (photoInput && photoPreview && previewPhoto) {
    const readFile = (file) => {
      if (!file || !file.type.startsWith('image/')) return;
      const reader = new FileReader();
      reader.onload = (event) => {
        photoPreview.src = event.target.result;
        previewPhoto.src = event.target.result;
        photoPreview.hidden = false;
        previewPhoto.hidden = false;
      };
      reader.readAsDataURL(file);
    };

    photoInput.addEventListener('change', (event) => {
      readFile(event.target.files[0]);
      syncPreview();
    });

    if (dropzone) {
      ['dragenter', 'dragover'].forEach((eventName) => {
        dropzone.addEventListener(eventName, (event) => {
          event.preventDefault();
          dropzone.classList.add('is-dragover');
        });
      });

      ['dragleave', 'drop'].forEach((eventName) => {
        dropzone.addEventListener(eventName, (event) => {
          event.preventDefault();
          dropzone.classList.remove('is-dragover');
        });
      });

      dropzone.addEventListener('drop', (event) => {
        const file = event.dataTransfer.files[0];
        if (file) {
          photoInput.files = event.dataTransfer.files;
          readFile(file);
        }
      });
    }
  }

  ['first_name', 'last_name', 'student_class', 'school'].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('input', syncPreview);
  });
  if (examCategory) examCategory.addEventListener('change', syncPreview);

  const qrUpload = document.getElementById('qr-upload');
  const qrJson = document.getElementById('qr_json');
  if (qrUpload && qrJson) {
    qrUpload.addEventListener('change', async (event) => {
      const file = event.target.files[0];
      if (!file) return;
      try {
        const text = await file.text();
        qrJson.value = text;
      } catch (error) {
        console.warn('Impossible de lire le fichier QR localement.');
      }
    });
  }

  const scanButton = document.getElementById('start-qr-scan');
  const cameraPreview = document.getElementById('qr-camera');
  const scanStatus = document.getElementById('qr-scan-status');
  const verifyForm = document.querySelector('.verify-form');
  let cameraStream;
  let scanning = false;
  const stopQrCamera = () => {
    scanning = false;
    if (cameraStream) cameraStream.getTracks().forEach((track) => track.stop());
    cameraStream = undefined;
    if (cameraPreview) {
      cameraPreview.srcObject = null;
      cameraPreview.hidden = true;
    }
  };

  if (scanButton && cameraPreview && scanStatus && qrJson && verifyForm) {
    scanButton.addEventListener('click', async () => {
      if (!('BarcodeDetector' in window) || !navigator.mediaDevices?.getUserMedia) {
        scanStatus.textContent = 'La caméra QR n’est pas disponible dans ce navigateur. Importez une image ou collez le code QR.';
        return;
      }
      try {
        stopQrCamera();
        const detector = new BarcodeDetector({ formats: ['qr_code'] });
        cameraStream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: { ideal: 'environment' } },
          audio: false,
        });
        cameraPreview.srcObject = cameraStream;
        cameraPreview.hidden = false;
        await cameraPreview.play();
        scanStatus.textContent = 'Caméra active. Placez le QR dans le cadre.';
        scanning = true;

        const scanFrame = async () => {
          if (!scanning) return;
          try {
            const codes = await detector.detect(cameraPreview);
            if (codes.length && codes[0].rawValue) {
              qrJson.value = codes[0].rawValue;
              scanStatus.textContent = 'QR détecté. Vérification en cours.';
              stopQrCamera();
              verifyForm.requestSubmit();
              return;
            }
          } catch {
            stopQrCamera();
            scanStatus.textContent = 'Lecture impossible. Importez une image ou collez le code QR.';
            return;
          }
          if (scanning) requestAnimationFrame(scanFrame);
        };
        requestAnimationFrame(scanFrame);
      } catch {
        stopQrCamera();
        scanStatus.textContent = 'Accès caméra refusé ou indisponible. Vérifiez les permissions du navigateur.';
      }
    });
    window.addEventListener('pagehide', stopQrCamera, { once: true });
  }

  if (issueForm) {
    issueForm.addEventListener('submit', () => {
      const submitButton = document.getElementById('issue-submit');
      if (submitButton) {
        submitButton.disabled = true;
        submitButton.textContent = 'Génération…';
      }
    });
  }

  const revealTargets = document.querySelectorAll('.reveal-target');
  revealTargets.forEach((target) => {
    target.style.opacity = '0';
    target.style.transform = 'translateY(18px)';
    target.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
    requestAnimationFrame(() => {
      target.style.opacity = '1';
      target.style.transform = 'translateY(0)';
    });
  });
});
