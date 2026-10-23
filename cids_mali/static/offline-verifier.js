'use strict';

const required = ['v','student_id','issuer_id','encrypted_data','issued_at','expires_at','signature'];
const statusNode = document.getElementById('status');
const resultNode = document.getElementById('result');
let displayedPhotoUrl;
const asBytes = (text) => Uint8Array.from(atob(text), (character) => character.charCodeAt(0));
const pemBytes = (pem) => asBytes(pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s/g, ''));
const signedBytes = (payload) => {
  const signed = {version: payload.v, student_id: payload.student_id, issuer_id: payload.issuer_id, encrypted_data: payload.encrypted_data, issued_at: payload.issued_at, expires_at: payload.expires_at};
  const ordered = Object.keys(signed).sort().map((key) => `${JSON.stringify(key)}: ${JSON.stringify(signed[key])}`).join(', ');
  return new TextEncoder().encode(`{${ordered}}`);
};
const showResult = (valid, reason, data, photoUrl) => {
  resultNode.replaceChildren(); resultNode.hidden = false; resultNode.className = `result${valid ? ' ok' : ''}`;
  const heading = document.createElement('h2'); heading.textContent = valid ? 'Valid card' : reason; resultNode.append(heading);
  if (data) {
    if (photoUrl) {
      const photo = document.createElement('img');
      photo.className = 'student-photo';
      photo.alt = 'Verified student photo';
      photo.src = photoUrl;
      resultNode.append(photo);
    }
    const list = document.createElement('dl');
    for (const key of ['exam_category','first_name','last_name','class','school','date_of_birth']) {
      const label = document.createElement('dt'); label.textContent = key === 'exam_category' ? 'Examen' : key.replace('_',' ');
      const value = document.createElement('dd'); value.textContent = data[key] ?? '';
      list.append(label,value);
    }
    resultNode.append(list);
  }
};

const camera = document.getElementById('camera');
const scanButton = document.getElementById('scan-toggle');
let cameraStream;
let scanning = false;
scanButton.addEventListener('click', async () => {
  if (scanning) {
    scanning = false;
    cameraStream?.getTracks().forEach((track) => track.stop());
    camera.hidden = true;
    scanButton.textContent = 'Open camera scanner';
    return;
  }
  if (!('BarcodeDetector' in window) || !navigator.mediaDevices?.getUserMedia) {
    statusNode.textContent = 'Camera QR scanning is unavailable in this browser. Paste the QR JSON below.';
    return;
  }
  try {
    const detector = new BarcodeDetector({formats:['qr_code']});
    cameraStream = await navigator.mediaDevices.getUserMedia({video:{facingMode:'environment'},audio:false});
    camera.srcObject = cameraStream;
    await camera.play();
    camera.hidden = false;
    scanning = true;
    scanButton.textContent = 'Close camera scanner';
    const scanFrame = async () => {
      if (!scanning) return;
      try {
        const codes = await detector.detect(camera);
        if (codes.length && codes[0].rawValue) {
          document.getElementById('qr').value = codes[0].rawValue;
          statusNode.textContent = 'QR captured. Select Verify locally.';
          scanning = false;
          cameraStream.getTracks().forEach((track) => track.stop());
          camera.hidden = true;
          scanButton.textContent = 'Open camera scanner';
          return;
        }
      } catch {}
      requestAnimationFrame(scanFrame);
    };
    requestAnimationFrame(scanFrame);
  } catch {
    statusNode.textContent = 'Camera access failed. Paste the QR JSON below.';
  }
});

document.getElementById('verify-form').addEventListener('submit', async (event) => {
  event.preventDefault(); resultNode.hidden = true; statusNode.textContent = 'Checking signature and card status…';
  if (displayedPhotoUrl) URL.revokeObjectURL(displayedPhotoUrl);
  displayedPhotoUrl = undefined;
  try {
    const payload = JSON.parse(document.getElementById('qr').value);
    if (!payload || Object.keys(payload).sort().join('|') !== [...required].sort().join('|') || payload.v !== 1) throw new Error('Corrupted data');
    if (payload.issuer_id !== document.getElementById('issuer-id').value.trim()) throw new Error('Unknown issuer');
    const publicPem = await document.getElementById('public-key').files[0].text();
    const publicKey = await crypto.subtle.importKey('spki', pemBytes(publicPem), {name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'}, false, ['verify']);
    const verified = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, asBytes(payload.signature), signedBytes(payload));
    if (!verified) throw new Error('Invalid signature – tampering detected');
    const now = new Date(); const expires = new Date(payload.expires_at); const issued = new Date(payload.issued_at);
    if (!Number.isFinite(expires.getTime()) || !Number.isFinite(issued.getTime()) || expires <= issued) throw new Error('Corrupted data');
    const cardExpired = now > expires;
    const age = (now-issued)/1000;
    if (document.getElementById('exam-mode').checked && (age < 0 || age > 3600)) throw new Error('QR expired – possible replay');
    const revocationFile = document.getElementById('revocations').files[0];
    const cardRevoked = revocationFile && (await revocationFile.text()).split(/\r?\n/).includes(payload.student_id);
    const aesRaw = new Uint8Array(await document.getElementById('aes-key').files[0].arrayBuffer());
    if (aesRaw.length !== 32) throw new Error('Corrupted data');
    const encrypted = asBytes(payload.encrypted_data); const aesKey = await crypto.subtle.importKey('raw', aesRaw, 'AES-CBC', false, ['decrypt']);
    let clear;
    try { clear = await crypto.subtle.decrypt({name:'AES-CBC',iv:encrypted.slice(0,16)}, aesKey, encrypted.slice(16)); }
    catch { throw new Error('Corrupted data'); }
    let clearBytes = new Uint8Array(clear);
    const decoded = new TextDecoder().decode(clearBytes);
    if (decoded.startsWith('c1:')) {
      if (!('DecompressionStream' in window)) throw new Error('Corrupted data');
      const compressed = clearBytes.slice(3);
      const decompressed = await new Response(new Blob([compressed]).stream().pipeThrough(new DecompressionStream('deflate'))).arrayBuffer();
      clearBytes = new Uint8Array(decompressed);
    } else if (decoded.startsWith('u1:')) {
      clearBytes = clearBytes.slice(3);
    }
    let personal = JSON.parse(new TextDecoder().decode(clearBytes));
    const compactFields = {ln:'last_name',fn:'first_name',dob:'date_of_birth',cl:'class',sc:'school',ph:'photo_hash',ni:'nina',ex:'exam_category'};
    if (Object.keys(personal).some((field) => field in compactFields)) {
      if (Object.keys(personal).some((field) => !(field in compactFields))) throw new Error('Corrupted data');
      personal = Object.fromEntries(Object.entries(personal).map(([key,value]) => [compactFields[key],value]));
    }
    const requiredPersonal = ['last_name','first_name','date_of_birth','class','school','photo_hash'];
    const permittedPersonal = [...requiredPersonal,'nina','exam_category'];
    if (!personal || requiredPersonal.some((field) => typeof personal[field] !== 'string') || Object.keys(personal).some((field) => !permittedPersonal.includes(field)) || ('nina' in personal && personal.nina !== null && typeof personal.nina !== 'string')) throw new Error('Corrupted data');
    personal.exam_category ??= 'DEF';
    if (!['DEF','BAC','CAP','BT1','BT2','IFM'].includes(personal.exam_category)) throw new Error('Corrupted data');
    const photoFile = document.getElementById('student-photo').files[0];
    if (photoFile) {
      if (photoFile.type !== 'image/png' || photoFile.size > 5 * 1024 * 1024) throw new Error('Photo hash mismatch');
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', await photoFile.arrayBuffer()));
      const actualHash = Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
      if (actualHash !== personal.photo_hash) throw new Error('Photo hash mismatch');
      displayedPhotoUrl = URL.createObjectURL(photoFile);
    }
    if (cardRevoked) showResult(false, 'Card revoked', personal, displayedPhotoUrl);
    else if (cardExpired) showResult(false, 'Card expired', personal, displayedPhotoUrl);
    else showResult(true, 'Valid card', personal, displayedPhotoUrl);
    statusNode.textContent = '';
  } catch (error) {
    const knownReasons = ['Unknown issuer','Invalid signature – tampering detected','Card expired','QR expired – possible replay','Card revoked','Corrupted data','Photo hash mismatch'];
    showResult(false, knownReasons.includes(error.message) ? error.message : 'Corrupted data'); statusNode.textContent = '';
  }
});