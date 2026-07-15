const state = {
  topicIndex: 0,
  step: 0,
  questionIndex: 0,
  answers: [],
  sound: false,
  examMode: false,
  progress: loadProgress()
};

const els = {
  list: document.querySelector("#topic-list"),
  content: document.querySelector("#lesson-content"),
  insight: document.querySelector("#insight-content"),
  next: document.querySelector("#next-button"),
  back: document.querySelector("#back-button"),
  dots: document.querySelector("#step-dots"),
  breadcrumb: document.querySelector("#breadcrumb"),
  context: document.querySelector("#header-context"),
  overallBar: document.querySelector("#overall-bar"),
  overallPercent: document.querySelector("#overall-percent"),
  mobileTitle: document.querySelector("#mobile-title"),
  mobileProgress: document.querySelector("#mobile-progress"),
  curriculum: document.querySelector("#curriculum"),
  scrim: document.querySelector("#scrim"),
  toast: document.querySelector("#toast")
};

function loadProgress() {
  try { return JSON.parse(localStorage.getItem("sarf-atlasi-progress")) || {}; }
  catch { return {}; }
}

function saveProgress() {
  localStorage.setItem("sarf-atlasi-progress", JSON.stringify(state.progress));
}

function currentTopic() {
  if (state.examMode) return examTopic();
  return TOPICS[state.topicIndex];
}

function examTopic() {
  return {
    id: "karma-sinav", title: "Karma Sınav", subtitle: "Tüm konulardan hızlı tarama", duration: "15 dk", level: "Sınav",
    intro: "Her konudan bir soru. İpucu yok; cevap verdikten sonra kısa açıklama var.",
    goal: "Hangi konuların tekrar istediğini görmek", memory: "Önce kalıbı tara, sonra kökü ve bağlamı kontrol et.",
    rule: "Soruyu aceleyle çevirmek yerine kelimenin <b>ek harflerini ve hareke düzenini</b> işaretle.",
    pattern: { from: "11 KONU", fromTr: "karma tarama", to: "11 SORU", toTr: "anlık seviye haritası" },
    concepts: [
      { ar: "01", title: "Kalıbı bul", text: "Baştaki مَ / مِ / مُ ve ortadaki elif-yâ-vav işaretlerini tara." },
      { ar: "02", title: "Görevi sor", text: "Kim, ne, nerede, neyle, daha mı, bir kez mi?" }
    ], examples: [], questions: EXAM_QUESTIONS
  };
}

function topicProgress(topic) {
  return state.progress[topic.id] || { complete: false, score: null, maxStep: 0 };
}

function setTopic(index) {
  state.examMode = false;
  state.topicIndex = index;
  state.step = 0;
  state.questionIndex = 0;
  state.answers = [];
  closeMenu();
  render();
}

function render() {
  const topic = currentTopic();
  renderNav();
  renderHeader(topic);
  renderDots();
  renderInsight(topic);

  if (state.step === 0) renderIntro(topic);
  else if (state.step === 1) renderConcepts(topic);
  else if (state.step === 2) renderExamples(topic);
  else if (state.step === 3) renderPractice(topic);
  else renderComplete(topic);

  els.back.disabled = state.step === 0;
  els.next.style.display = state.step === 3 ? "none" : "inline-flex";
  els.next.innerHTML = state.step === 0 ? "Derse başla <span>→</span>" : state.step === 4 ? nextTopicLabel() : "Devam et <span>→</span>";
  els.content.scrollTop = 0;
}

function renderNav() {
  els.list.innerHTML = TOPICS.map((topic, index) => {
    const p = topicProgress(topic);
    return `<button class="topic-item ${!state.examMode && index === state.topicIndex ? "active" : ""} ${p.complete ? "complete" : ""}" data-index="${index}">
      <span class="topic-number">${p.complete ? "✓" : String(index + 1).padStart(2, "0")}</span>
      <span class="topic-label"><strong>${topic.title}</strong><small>${topic.duration} · ${topic.level}</small></span>
      <span class="topic-state">${p.complete ? "●" : "›"}</span>
    </button>`;
  }).join("");
  els.list.querySelectorAll(".topic-item").forEach(button => button.addEventListener("click", () => setTopic(Number(button.dataset.index))));
  const completed = TOPICS.filter(t => topicProgress(t).complete).length;
  const percent = Math.round(completed / TOPICS.length * 100);
  els.overallBar.style.width = `${percent}%`;
  els.overallPercent.textContent = `${percent}%`;
  els.mobileProgress.textContent = `${percent}%`;
}

function renderHeader(topic) {
  els.breadcrumb.textContent = `ÖĞRENME ROTASI / ${topic.title.toLocaleUpperCase("tr-TR")} / ADIM ${state.step + 1}`;
  els.context.textContent = `${topic.title} · ${topic.subtitle}`;
  els.mobileTitle.textContent = topic.title;
}

function renderDots() {
  els.dots.innerHTML = Array.from({ length: 5 }, (_, i) => `<span class="step-dot ${i === state.step ? "active" : i < state.step ? "done" : ""}"></span>`).join("");
}

function renderInsight(topic) {
  const p = topicProgress(topic);
  const labels = ["Kavramı tanı", "Kalıbı çöz", "Örnekleri incele", "Kendini dene", "Dersi tamamla"];
  els.insight.innerHTML = `
    <div class="insight-number">${String(state.examMode ? 12 : state.topicIndex + 1).padStart(2, "0")}</div>
    <h2>${labels[state.step]}</h2>
    <p>${topic.goal}</p>
    <div class="insight-divider"></div>
    <div class="insight-stat"><span>Seviye</span><strong>${topic.level}</strong></div>
    <div class="insight-stat"><span>Süre</span><strong>${topic.duration}</strong></div>
    <div class="insight-stat"><span>En iyi skor</span><strong>${p.score == null ? "—" : `%${p.score}`}</strong></div>
    <div class="tip-box"><span>HAFIZA ÇENGELİ</span><p>${topic.memory}</p></div>`;
}

function renderIntro(topic) {
  els.content.innerHTML = `<div class="content-inner">
    <div class="lesson-kicker">${topic.level} · ${topic.duration}</div>
    <h2 class="lesson-title">${topic.title}</h2>
    <p class="lesson-lead">${topic.intro}</p>
    <div class="hero-pattern">
      <div class="pattern-side"><small>Başlangıç</small><strong class="arabic">${topic.pattern.from}</strong><strong>${topic.pattern.fromTr}</strong></div>
      <div class="pattern-arrow"></div>
      <div class="pattern-side"><small>Sonuç</small><strong class="arabic">${topic.pattern.to}</strong><strong>${topic.pattern.toTr}</strong></div>
    </div>
    <div class="key-rule"><strong>Bu derste hedef:</strong> ${topic.goal}.</div>
  </div>`;
}

function renderConcepts(topic) {
  els.content.innerHTML = `<div class="content-inner">
    <div class="lesson-kicker">Kuralı gör</div>
    <h2 class="lesson-title">Kalıbı parçalara ayır.</h2>
    <p class="lesson-lead">${topic.narrative}</p>
    <div class="rule-panel">
      <span class="rule-panel-label">TEMEL KURAL</span>
      <p>${topic.rule}</p>
    </div>
    <div class="concept-grid">${topic.concepts.map(c => `<article class="concept-card"><span class="arabic">${c.ar}</span><strong>${c.title}</strong><p>${c.text}</p></article>`).join("")}</div>
    <section class="method-section">
      <div class="section-heading"><span>UYGULAMA YÖNTEMİ</span><h3>Üç adımda teşhis et</h3></div>
      <div class="method-list">${topic.process.map((item, i) => `<div class="method-row"><span class="method-number">${String(i + 1).padStart(2, "0")}</span><div><strong>${item.title}</strong><p>${item.text}</p></div></div>`).join("")}</div>
    </section>
  </div>`;
}

function renderExamples(topic) {
  const rows = topic.examples.length ? topic.examples.map(e => `<div class="example-row"><span class="arabic">${e.ar}</span><p>${e.tr}</p><small>${e.tag}</small></div>`).join("") : `<div class="key-rule">Sınav modunda örnek çözüm gösterilmez. Hazır olduğunda devam et.</div>`;
  els.content.innerHTML = `<div class="content-inner">
    <div class="lesson-kicker">Bağlamda gör</div>
    <h2 class="lesson-title">Kalıp cümlede canlansın.</h2>
    <p class="lesson-lead">Arapça ifadeyi önce kendin çöz. Sonra Türkçe anlamla karşılaştır ve kalıbın cümlede hangi soruya cevap verdiğini bul.</p>
    <div class="example-stack">${rows}</div>
    <div class="worked-example">
      <span class="worked-icon">↳</span>
      <div><span class="worked-label">ÖRNEK ÇÖZÜMÜN MANTIĞI</span><p>${topic.exampleNote}</p></div>
    </div>
    <section class="pitfall-section">
      <div class="section-heading"><span>DİKKAT NOKTASI</span><h3>En sık karıştırılanlar</h3></div>
      <div class="pitfall-list">${topic.pitfalls.map((text, i) => `<div><span>${i + 1}</span><p>${text}</p></div>`).join("")}</div>
    </section>
  </div>`;
}

function renderPractice(topic) {
  if (state.questionIndex >= topic.questions.length) {
    finishPractice(topic);
    return;
  }
  const q = topic.questions[state.questionIndex];
  els.content.innerHTML = `<div class="content-inner">
    <div class="practice-head"><div><div class="lesson-kicker">Bilgiyi geri çağır</div><h2 class="lesson-title" style="font-size:32px;margin-bottom:0">Mini alıştırma</h2></div><span class="practice-counter">${state.questionIndex + 1} / ${topic.questions.length}</span></div>
    <div class="question-card">
      <span class="question-label">${state.examMode ? q.topic.toLocaleUpperCase("tr-TR") : "TEK CEVAP"}</span>
      <div class="question-text">${q.q}</div>
      <div class="option-list">${q.options.map((option, i) => `<button class="option" data-option="${i}"><span class="letter">${String.fromCharCode(65 + i)}</span><span class="${/[\u0600-\u06FF]/.test(option) ? "arabic" : ""}">${option}</span></button>`).join("")}</div>
      <div class="feedback" id="feedback"></div>
      <button class="button primary inline-next" id="question-next" style="display:none">${state.questionIndex === topic.questions.length - 1 ? "Sonucu gör" : "Sıradaki soru"} →</button>
      <div style="clear:both"></div>
    </div>
  </div>`;
  els.content.querySelectorAll(".option").forEach(button => button.addEventListener("click", () => answerQuestion(Number(button.dataset.option))));
}

function answerQuestion(choice) {
  const topic = currentTopic();
  const q = topic.questions[state.questionIndex];
  const buttons = [...els.content.querySelectorAll(".option")];
  buttons.forEach((button, i) => {
    button.disabled = true;
    if (i === q.answer) button.classList.add("correct");
    if (i === choice && choice !== q.answer) button.classList.add("wrong");
  });
  const correct = choice === q.answer;
  state.answers.push(correct);
  const feedback = document.querySelector("#feedback");
  feedback.className = `feedback show ${correct ? "correct" : "wrong"}`;
  feedback.innerHTML = `<strong>${correct ? "Doğru." : "Henüz değil."}</strong> ${q.why}`;
  const next = document.querySelector("#question-next");
  next.style.display = "inline-block";
  next.addEventListener("click", () => { state.questionIndex++; renderPractice(topic); });
  if (state.sound) playTone(correct ? 620 : 240);
}

function finishPractice(topic) {
  const score = Math.round(state.answers.filter(Boolean).length / topic.questions.length * 100);
  if (!state.progress[topic.id]) state.progress[topic.id] = {};
  state.progress[topic.id].score = Math.max(state.progress[topic.id].score || 0, score);
  state.progress[topic.id].complete = score >= 60;
  state.progress[topic.id].maxStep = 4;
  saveProgress();
  state.step = 4;
  render();
}

function renderComplete(topic) {
  const p = topicProgress(topic);
  const score = p.score ?? 0;
  const passed = score >= 60;
  els.content.innerHTML = `<div class="content-inner complete-view">
    <div class="complete-icon">${passed ? "✓" : "↻"}</div>
    <div class="lesson-kicker" style="justify-content:center">${passed ? "Ders tamamlandı" : "Bir tur daha"}</div>
    <h2 class="lesson-title" style="margin-left:auto;margin-right:auto">${passed ? "Kalıp artık haritanda." : "Temel hazır, biraz pekiştirelim."}</h2>
    <p class="lesson-lead">${passed ? `${topic.title} alıştırmasını tamamladın. Bir sonraki konuya geçebilir veya bu dersi yeniden çözebilirsin.` : "Bu turda geçme eşiği olan %60’a ulaşamadın. Kural kartlarına kısa bir bakış daha atıp tekrar dene."}</p>
    <div class="score-ring" style="--score:${score}%"><strong>%${score}</strong></div>
    <button class="button secondary" id="retry-button">Alıştırmayı tekrar çöz</button>
    <div class="memory-strip">
      <div><small>Kavram</small><strong>${topic.title}</strong></div>
      <div><small>Ana hedef</small><strong>${topic.goal}</strong></div>
      <div><small>Hafıza çengeli</small><strong>${topic.memory}</strong></div>
    </div>
  </div>`;
  document.querySelector("#retry-button").addEventListener("click", () => { state.step = 3; state.questionIndex = 0; state.answers = []; render(); });
}

function nextTopicLabel() {
  if (state.examMode) return "Rotaya dön →";
  if (state.topicIndex === TOPICS.length - 1) return "Başa dön →";
  return "Sonraki konu →";
}

function goNext() {
  const topic = currentTopic();
  if (state.step < 4) {
    state.step++;
    if (!state.progress[topic.id]) state.progress[topic.id] = {};
    state.progress[topic.id].maxStep = Math.max(state.progress[topic.id].maxStep || 0, state.step);
    saveProgress();
    render();
  } else if (state.examMode) {
    state.examMode = false; state.step = 0; state.questionIndex = 0; state.answers = []; render();
  } else {
    state.topicIndex = (state.topicIndex + 1) % TOPICS.length;
    state.step = 0; state.questionIndex = 0; state.answers = []; render();
  }
}

function goBack() {
  if (state.step === 0) return;
  state.step--;
  if (state.step === 3) { state.questionIndex = 0; state.answers = []; }
  render();
}

function startExam() {
  state.examMode = true;
  state.step = 0;
  state.questionIndex = 0;
  state.answers = [];
  closeMenu();
  render();
}

function openMenu() { els.curriculum.classList.add("open"); els.scrim.classList.add("show"); }
function closeMenu() { els.curriculum.classList.remove("open"); els.scrim.classList.remove("show"); }
function showToast(text) { els.toast.textContent = text; els.toast.classList.add("show"); setTimeout(() => els.toast.classList.remove("show"), 1800); }
function playTone(frequency) {
  const audio = new (window.AudioContext || window.webkitAudioContext)();
  const osc = audio.createOscillator(); const gain = audio.createGain();
  osc.frequency.value = frequency; gain.gain.setValueAtTime(.06, audio.currentTime); gain.gain.exponentialRampToValueAtTime(.001, audio.currentTime + .18);
  osc.connect(gain).connect(audio.destination); osc.start(); osc.stop(audio.currentTime + .18);
}

els.next.addEventListener("click", goNext);
els.back.addEventListener("click", goBack);
document.querySelector("#exam-button").addEventListener("click", startExam);
document.querySelector("#menu-button").addEventListener("click", openMenu);
document.querySelector("#close-menu").addEventListener("click", closeMenu);
els.scrim.addEventListener("click", closeMenu);
document.querySelector("#sound-toggle").addEventListener("click", event => {
  state.sound = !state.sound;
  event.currentTarget.setAttribute("aria-pressed", String(state.sound));
  event.currentTarget.querySelector("span").textContent = state.sound ? "Sesler açık" : "Sesler kapalı";
  showToast(state.sound ? "Geri bildirim sesleri açıldı" : "Geri bildirim sesleri kapatıldı");
});
document.querySelector("#reset-button").addEventListener("click", () => {
  if (confirm("Tüm ders ilerlemesi sıfırlansın mı?")) { state.progress = {}; saveProgress(); state.step = 0; render(); showToast("İlerleme sıfırlandı"); }
});
document.addEventListener("keydown", event => {
  if (event.target.closest("button") || state.step === 3) return;
  if (event.key === "ArrowRight") goNext();
  if (event.key === "ArrowLeft") goBack();
});

render();
