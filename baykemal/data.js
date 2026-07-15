const TOPICS = [
  {
    id: "zaman", title: "İsm-i Zaman", subtitle: "Eylemin gerçekleştiği zaman", duration: "8 dk", level: "Temel",
    intro: "Bir fiilin ne zaman gerçekleştiğini tek kelimeyle işaretleyen türemiş isimdir.",
    goal: "مَفْعَل ve مَفْعِل kalıplarını ayırt etmek",
    memory: "Başındaki مَ ‘zaman/yer kapısıdır’; anlamı cümle belirler.",
    rule: "Sülâsî fiillerde çoğunlukla <b>مَفْعَلٌ</b> veya <b>مَفْعِلٌ</b>; sülâsî olmayanlarda ism-i mef‘ûl kalıbı kullanılır.",
    pattern: { from: "وَعَدَ", fromTr: "söz verdi", to: "مَوْعِدٌ", toTr: "buluşma / söz zamanı" },
    concepts: [
      { ar: "مَفْعَلٌ", title: "Mef‘al kalıbı", text: "Muzârinin aynü’l-fiili üstünse veya fiil nâkıssa sık görülür: مَلْعَبٌ." },
      { ar: "مَفْعِلٌ", title: "Mef‘il kalıbı", text: "Muzârinin aynü’l-fiili esreliyse veya başı vavlı misalse sık görülür: مَوْعِدٌ." }
    ],
    examples: [
      { ar: "مَوْعِدُ الدَّرْسِ صَبَاحًا", tr: "Dersin zamanı sabahtır.", tag: "zaman" },
      { ar: "مَوْلِدُ النَّبِيِّ", tr: "Peygamber'in doğum zamanı / mevlidi", tag: "zaman" },
      { ar: "مَغْرِبُ الشَّمْسِ", tr: "Güneşin batış zamanı", tag: "zaman" }
    ],
    questions: [
      { q: "<span class='arabic'>مَوْعِدٌ</span> kelimesinin bu dersteki temel işlevi nedir?", options: ["Eylemi yapanı gösterir", "Eylemin zamanını gösterir", "Eylemin aracını gösterir", "Küçültme bildirir"], answer: 1, why: "مَوْعِدٌ, وَعَدَ fiilinden türeyerek belirlenmiş zamanı ifade eder." },
      { q: "Aşağıdakilerden hangisi ism-i zaman olabilir?", options: ["مَغْرِبٌ", "كَاتِبٌ", "مَكْتُوبٌ", "مِفْتَاحٌ"], answer: 0, why: "مَغْرِبٌ bağlama göre güneşin batış zamanını anlatır." },
      { q: "İsm-i zaman ile ism-i mekân aynı kalıptaysa farkı ne belirler?", options: ["Harf sayısı", "Cümledeki anlam ve bağlam", "Kelimenin cinsiyeti", "Daima son hareke"], answer: 1, why: "Biçimleri aynı olabilir; zaman mı yer mi olduğu bağlamdan anlaşılır." }
    ]
  },
  {
    id: "mekan", title: "İsm-i Mekân", subtitle: "Eylemin gerçekleştiği yer", duration: "8 dk", level: "Temel",
    intro: "Fiilin gerçekleştiği yeri gösterir. Türkçedeki ‘-lık, yer’ fikrine yakındır.", goal: "Yer bildiren türemiş isimleri bağlamda tanımak",
    memory: "مَكْتَب: yazılan yer → ofis. Önce fiili bul, sonra ‘nerede?’ diye sor.",
    rule: "Sülâsî fiillerden <b>مَفْعَلٌ / مَفْعِلٌ</b> ile yapılır. Bazı kelimelere bolluk bildiren ة eklenebilir: مَكْتَبَةٌ.",
    pattern: { from: "كَتَبَ", fromTr: "yazdı", to: "مَكْتَبٌ", toTr: "yazı yazılan yer / ofis" },
    concepts: [
      { ar: "مَجْلِسٌ", title: "Oturma yeri", text: "جَلَسَ (oturdu) fiilinden: meclis, oturulan/toplanılan yer." },
      { ar: "مَلْعَبٌ", title: "Oyun alanı", text: "لَعِبَ (oynadı) fiilinden: oyun oynanan yer, saha." }
    ],
    examples: [
      { ar: "ذَهَبْتُ إِلَى الْمَكْتَبِ", tr: "Ofise gittim.", tag: "nerede?" },
      { ar: "هٰذَا مَدْخَلُ الْمَدْرَسَةِ", tr: "Burası okulun girişidir.", tag: "nerede?" },
      { ar: "الْأَطْفَالُ فِي الْمَلْعَبِ", tr: "Çocuklar oyun alanındadır.", tag: "nerede?" }
    ],
    questions: [
      { q: "<span class='arabic'>لَعِبَ</span> fiilinden ‘oyun oynanan yer’ hangisidir?", options: ["لَاعِبٌ", "مَلْعَبٌ", "مَلْعُوبٌ", "مِلْعَبٌ"], answer: 1, why: "مَلْعَبٌ, مَفْعَلٌ kalıbında ‘oyun yeri’dir." },
      { q: "<span class='arabic'>مَجْلِسٌ</span> kelimesinin kök anlamıyla en yakın açıklaması nedir?", options: ["Oturma yeri", "Yazma aracı", "Yazılmış şey", "En güzel"], answer: 0, why: "جَلَسَ ‘oturdu’ fiilinden, oturulan/toplanılan yeri bildirir." },
      { q: "Hangisi ism-i mekân değildir?", options: ["مَدْخَلٌ", "مَخْرَجٌ", "مَكْتَبٌ", "كَاتِبٌ"], answer: 3, why: "كَاتِبٌ ism-i fâildir; ‘yazan’ demektir." }
    ]
  },
  {
    id: "tafdil", title: "İsm-i Tafdîl", subtitle: "Üstünlük ve karşılaştırma", duration: "10 dk", level: "Orta",
    intro: "İki varlık arasında bir özelliğin daha fazla olduğunu veya bir varlığın en üstün olduğunu anlatır.", goal: "أَفْعَلُ kalıbını karşılaştırmada kullanmak",
    memory: "أَكْبَرُ = daha büyük / en büyük. ‘Daha mı, en mi?’ sorusunu yapı belirler.",
    rule: "Temel kalıp <b>أَفْعَلُ</b>’dür. ‘-den daha’ karşılaştırmasında ardından مِنْ; üstünlükte çoğunlukla ال veya tamlama gelir.",
    pattern: { from: "كَبُرَ", fromTr: "büyük oldu", to: "أَكْبَرُ", toTr: "daha büyük / en büyük" },
    concepts: [
      { ar: "أَكْبَرُ مِنْ", title: "Karşılaştırma", text: "مِنْ ile: Ali, Hasan’dan daha büyüktür." },
      { ar: "الْأَكْبَرُ", title: "Üstünlük", text: "ال takısı veya tamlama ile: en büyük öğrenci." }
    ],
    examples: [
      { ar: "عَلِيٌّ أَطْوَلُ مِنْ حَسَنٍ", tr: "Ali, Hasan’dan daha uzundur.", tag: "karşılaştırma" },
      { ar: "هٰذَا أَفْضَلُ كِتَابٍ", tr: "Bu, en iyi kitaptır.", tag: "üstünlük" },
      { ar: "الْعِلْمُ أَنْفَعُ مِنَ الْمَالِ", tr: "İlim maldan daha faydalıdır.", tag: "karşılaştırma" }
    ],
    questions: [
      { q: "‘Zeyd, Amr’dan daha büyüktür’ cümlesindeki doğru yapı hangisi?", options: ["زَيْدٌ كَبِيرٌ عَمْرًا", "زَيْدٌ أَكْبَرُ مِنْ عَمْرٍ", "زَيْدٌ مَكْبُورٌ", "زَيْدٌ كَابِرٌ مِنْ عَمْرٍ"], answer: 1, why: "أَكْبَرُ ism-i tafdîldir; karşılaştırılan ikinci unsur مِنْ ile gelir." },
      { q: "İsm-i tafdîlin temel kalıbı hangisidir?", options: ["فَاعِلٌ", "مَفْعُولٌ", "أَفْعَلُ", "فُعَيْلٌ"], answer: 2, why: "Üstünlük ve karşılaştırmanın temel vezni أَفْعَلُ’dür." },
      { q: "<span class='arabic'>هٰذَا أَفْضَلُ كِتَابٍ</span> ne anlatır?", options: ["Bu faydalı bir kitaptır", "Bu yazılmış kitaptır", "Bu en iyi kitaptır", "Bu küçük kitaptır"], answer: 2, why: "أَفْضَلُ tamlama içinde üstünlük, yani ‘en iyi’ anlamı verir." }
    ]
  },
  {
    id: "tasgir", title: "İsm-i Tasğîr", subtitle: "Küçültme ve sevimlilik", duration: "10 dk", level: "Orta",
    intro: "Bir varlığın küçüklüğünü, azlığını, yakınlığını veya bazen sevimliliğini gösterir.", goal: "فُعَيْلٌ ailesini görünce küçültme anlamını sezmek",
    memory: "İkinci harften sonra gelen يْ, tasğîrin görsel parmak izidir: كَلْب → كُلَيْب.",
    rule: "Üç harfli isimler çoğunlukla <b>فُعَيْلٌ</b>, dört harfliler <b>فُعَيْعِلٌ</b>, beş harfliler uygun eksiltmeyle <b>فُعَيْعِيلٌ</b> kalıbına yaklaşır.",
    pattern: { from: "كِتَابٌ", fromTr: "kitap", to: "كُتَيِّبٌ", toTr: "kitapçık" },
    concepts: [
      { ar: "جُبَيْلٌ", title: "Küçüklük", text: "جَبَلٌ (dağ) → جُبَيْلٌ (küçük dağ, tepecik)." },
      { ar: "بُنَيٌّ", title: "Sevgi / şefkat", text: "اِبْنٌ (oğul) → بُنَيٌّ (oğulcuğum)." }
    ],
    examples: [
      { ar: "رَأَيْتُ نُهَيْرًا", tr: "Küçük bir nehir gördüm.", tag: "küçüklük" },
      { ar: "يَا بُنَيَّ", tr: "Ey oğulcuğum!", tag: "şefkat" },
      { ar: "فِي الْبَيْتِ كُلَيْبٌ", tr: "Evde küçük bir köpek var.", tag: "küçüklük" }
    ],
    questions: [
      { q: "<span class='arabic'>جَبَلٌ</span> kelimesinin tasğîri hangisidir?", options: ["جَابِلٌ", "مَجْبُولٌ", "جُبَيْلٌ", "أَجْبَلُ"], answer: 2, why: "Üç harfli جَبَلٌ, فُعَيْلٌ kalıbında جُبَيْلٌ olur." },
      { q: "Tasğîr yalnızca fiziksel küçüklük mü bildirir?", options: ["Evet, daima", "Hayır; sevgi, azlık veya yakınlık da bildirebilir", "Yalnızca zaman bildirir", "Yalnızca araç bildirir"], answer: 1, why: "Tasğîr bağlama göre küçüklük yanında sevgi, azlık ve yakınlık ifade edebilir." },
      { q: "Tasğîr kelimelerinde sık görülen ayırt edici ses hangisidir?", options: ["İkinci harften sonraki يْ", "Baştaki مِ", "Sondaki ون", "Baştaki است"], answer: 0, why: "فُعَيْلٌ modelindeki يْ tasğîrin en güçlü görsel işaretidir." }
    ]
  },
  {
    id: "turemis", title: "Türemiş Fiiller", subtitle: "Mezîd bablar ve anlamları", duration: "14 dk", level: "İleri",
    intro: "Üç harfli köke bir veya daha çok harf eklenerek yeni anlam katılan fiillerdir.", goal: "Yaygın mezîd kalıpları anlam işaretleriyle eşleştirmek",
    memory: "Kök aynı, sahne değişir: عَلِمَ bildi → عَلَّمَ öğretti → تَعَلَّمَ öğrendi.",
    rule: "Ek harfler fiile ettirgenlik, karşılıklılık, çaba, dönüşlülük veya talep gibi anlamlar katar. Anlam her zaman mekanik değildir; sözlük kontrolü gerekir.",
    pattern: { from: "عَلِمَ", fromTr: "bildi (I. bâb)", to: "عَلَّمَ", toTr: "öğretti (II. bâb)" },
    concepts: [
      { ar: "فَعَّلَ / تَفَعَّلَ", title: "II ve V. bâb", text: "Ettirme/yoğunluk: عَلَّمَ; dönüşlü edinme: تَعَلَّمَ." },
      { ar: "أَفْعَلَ / اِسْتَفْعَلَ", title: "IV ve X. bâb", text: "Ettirme: أَخْرَجَ; isteme/talep: اِسْتَغْفَرَ." }
    ],
    examples: [
      { ar: "عَلَّمَ الْمُعَلِّمُ الطَّالِبَ", tr: "Öğretmen öğrenciye öğretti.", tag: "II. bâb" },
      { ar: "تَعَلَّمَ الطَّالِبُ", tr: "Öğrenci öğrendi.", tag: "V. bâb" },
      { ar: "اِسْتَغْفَرَ الْمُؤْمِنُ", tr: "Mümin bağışlanma diledi.", tag: "X. bâb" }
    ],
    questions: [
      { q: "<span class='arabic'>عَلِمَ → عَلَّمَ</span> dönüşümünde temel anlam değişimi nedir?", options: ["Bildi → öğretti", "Bildi → bilindi", "Bildi → daha bilgili", "Bildi → bilgi yeri"], answer: 0, why: "II. bâb burada fiili ettirgen yapar: bilmesini sağladı, öğretti." },
      { q: "<span class='arabic'>اِسْتَغْفَرَ</span> fiilindeki X. bâb çoğunlukla hangi fikri taşır?", options: ["Küçültme", "İsteme / talep", "Yer", "Üstünlük"], answer: 1, why: "اِسْتَغْفَرَ ‘bağışlanma istedi’ demektir; استـ çoğu örnekte talep fikri verir." },
      { q: "Mezîd fiillerin anlamı yalnız kalıptan kesin çıkarılabilir mi?", options: ["Her zaman", "Hayır; kalıp ipucu verir, kullanım ve sözlük belirler", "Sadece geçmiş zamanda", "Yalnız dört harfliyse"], answer: 1, why: "Bâbların genel anlam eğilimleri vardır; fakat her fiil bunlara mekanik biçimde uymaz." }
    ]
  },
  {
    id: "mastar", title: "Mastar", subtitle: "Fiilin yalın eylem adı", duration: "10 dk", level: "Temel",
    intro: "Zaman ve şahıs bildirmeden eylemin kendisini adlandırır: yazmak değil, ‘yazma / yazış’ fikri.", goal: "Fiil ile mastar arasındaki görev farkını görmek",
    memory: "Fiil olayın çekilmiş hâli; mastar olayın etiketidir: كَتَبَ yazdı → كِتَابَةٌ yazma.",
    rule: "Sülâsî mücerred fiillerin mastarları çoğunlukla semâîdir ve sözlükten öğrenilir. Mezîd fiillerin mastarları ise genellikle düzenli kalıplara sahiptir.",
    pattern: { from: "كَتَبَ", fromTr: "yazdı", to: "كِتَابَةٌ", toTr: "yazma / yazış" },
    concepts: [
      { ar: "فَهْمٌ", title: "Soyut eylem adı", text: "فَهِمَ (anladı) fiilinin mastarı: anlama, anlayış." },
      { ar: "خُرُوجٌ", title: "Zamansız olay", text: "خَرَجَ (çıktı) fiilinin mastarı: çıkma, çıkış." }
    ],
    examples: [
      { ar: "أُحِبُّ الْقِرَاءَةَ", tr: "Okumayı seviyorum.", tag: "mastar" },
      { ar: "طَلَبُ الْعِلْمِ مُهِمٌّ", tr: "İlim talep etmek önemlidir.", tag: "mastar" },
      { ar: "بَعْدَ الْخُرُوجِ", tr: "Çıkıştan / çıktıktan sonra", tag: "mastar" }
    ],
    questions: [
      { q: "<span class='arabic'>كَتَبَ</span> fiilinin eylem adı hangisidir?", options: ["كَاتِبٌ", "مَكْتُوبٌ", "كِتَابَةٌ", "مَكْتَبٌ"], answer: 2, why: "كِتَابَةٌ, zaman ve şahıs bildirmeden yazma eylemini adlandırır." },
      { q: "Sülâsî mücerred fiillerin mastarları için en güvenli yaklaşım nedir?", options: ["Tek kalıp uygulamak", "Sözlükten fiille birlikte öğrenmek", "Başına daima م eklemek", "Sonuna ون eklemek"], answer: 1, why: "Bu mastarlar büyük ölçüde semâîdir; fiille beraber ezberlenir." },
      { q: "Mastarın fiilden temel farkı nedir?", options: ["Daima çoğuldur", "Zaman ve şahıs bildirmez", "Yalnız yer bildirir", "Sadece edilgendir"], answer: 1, why: "Mastar olayın adıdır; çekimli fiil gibi zaman ve şahıs taşımaz." }
    ]
  },
  {
    id: "mastar-turleri", title: "Mastar Türleri", subtitle: "Mimî, merre, hey’et ve sınâî", duration: "13 dk", level: "İleri",
    intro: "Eylemi; sıradan bir ad, bir kez oluş, oluş biçimi veya soyut kavram olarak farklı açılardan adlandırabiliriz.", goal: "Dört yaygın mastar türünü biçim ve anlamla ayırmak",
    memory: "Bir kez = ة; nasıl = فِعْلَة; mimî = başta م; fikir/akım = ـِيَّة.",
    rule: "Mastar-ı merre bir defayı, nev‘/hey’et oluş tarzını, mimî م ile başlayan mastarlaşmayı, sınâî ise ـِيَّة ekiyle soyut kavramı gösterir.",
    pattern: { from: "جَلَسَ", fromTr: "oturdu", to: "جَلْسَةٌ", toTr: "bir kez oturuş / oturum" },
    concepts: [
      { ar: "مَدْخَلٌ", title: "Mastar-ı mimî", text: "Başında çoğunlukla زائد م bulunur; eylemin kendisini adlandırabilir." },
      { ar: "نَظْرَةٌ / جِلْسَةٌ", title: "Merre ve hey’et", text: "نَظْرَةٌ bir bakış; جِلْسَةٌ bağlama göre bir oturuş veya oturuş biçimi." },
      { ar: "إِنْسَانِيَّةٌ", title: "Mastar-ı sınâî", text: "İsme ـِيَّة ekleyerek soyut nitelik/kavram: insanlık." },
      { ar: "قِتَالٌ", title: "Aslî mastar", text: "Fiilin olay anlamını yalın biçimde taşır: savaşma/savaş." }
    ],
    examples: [
      { ar: "نَظَرْتُ نَظْرَةً", tr: "Bir kez baktım / bir bakış attım.", tag: "merre" },
      { ar: "جَلَسَ جِلْسَةَ الْعَالِمِ", tr: "Âlimin oturuşu gibi oturdu.", tag: "hey’et" },
      { ar: "الْحُرِّيَّةُ حَقٌّ", tr: "Özgürlük bir haktır.", tag: "sınâî" }
    ],
    questions: [
      { q: "‘Bir kez bakma / bir bakış’ anlamındaki <span class='arabic'>نَظْرَةٌ</span> hangi türdür?", options: ["Mastar-ı merre", "Mastar-ı mimî", "İsm-i âlet", "İsm-i tafdîl"], answer: 0, why: "Sülâsî fiilde فَعْلَةٌ görünümü çoğu kez bir defalık oluşu anlatır." },
      { q: "<span class='arabic'>إِنْسَانِيَّةٌ</span> hangi mastar türüne örnektir?", options: ["Hey’et", "Sınâî", "Merre", "Mimî"], answer: 1, why: "ـِيَّة ekiyle ‘insanlık’ soyut kavramı üretilmiştir." },
      { q: "Mastar-ı hey’et neyi öne çıkarır?", options: ["Eylemin yerini", "Eylemin bir kez oluşunu", "Eylemin yapılış biçimini", "Eylemin aracını"], answer: 2, why: "Hey’et mastarı eylemin nasıl, hangi görünüşte yapıldığını ifade eder." }
    ]
  },
  {
    id: "alet", title: "İsm-i Âlet", subtitle: "Eylemin aracı", duration: "9 dk", level: "Orta",
    intro: "Bir işin yapılmasında kullanılan araç veya gereci adlandıran türemiş isimdir.", goal: "Üç klasik araç kalıbını tanımak",
    memory: "Mekânın مَ’sı açık, âletin مِ’si aşağıdadır: مَكْتَب / مِفْتَاح.",
    rule: "Klasik kalıplar <b>مِفْعَلٌ، مِفْعَالٌ، مِفْعَلَةٌ</b>. Modern kullanımda فَعَّالَةٌ gibi kıyasî kalıplar da vardır; birçok araç adı semâîdir.",
    pattern: { from: "فَتَحَ", fromTr: "açtı", to: "مِفْتَاحٌ", toTr: "anahtar / açma aracı" },
    concepts: [
      { ar: "مِفْعَلٌ", title: "Kısa araç kalıbı", text: "مِبْرَدٌ: eğe; مِشْرَطٌ: neşter." },
      { ar: "مِفْعَالٌ", title: "Uzun araç kalıbı", text: "مِفْتَاحٌ: anahtar; مِنْشَارٌ: testere." },
      { ar: "مِفْعَلَةٌ", title: "Dişil araç kalıbı", text: "مِكْنَسَةٌ: süpürge; مِطْرَقَةٌ: çekiç." },
      { ar: "غَسَّالَةٌ", title: "Modern kalıp", text: "فَعَّالَةٌ kalıbında: çamaşır makinesi." }
    ],
    examples: [
      { ar: "فَتَحْتُ الْبَابَ بِالْمِفْتَاحِ", tr: "Kapıyı anahtarla açtım.", tag: "araç" },
      { ar: "كَنَسْتُ بِالْمِكْنَسَةِ", tr: "Süpürgeyle süpürdüm.", tag: "araç" },
      { ar: "قَطَعَ الْخَشَبَ بِالْمِنْشَارِ", tr: "Tahtayı testereyle kesti.", tag: "araç" }
    ],
    questions: [
      { q: "<span class='arabic'>فَتَحَ</span> ‘açtı’ fiilinin araç adı hangisidir?", options: ["مَفْتَحٌ", "فَاتِحٌ", "مِفْتَاحٌ", "مَفْتُوحٌ"], answer: 2, why: "مِفْتَاحٌ, مِفْعَالٌ kalıbında açma aracıdır." },
      { q: "Hangisi klasik ism-i âlet kalıplarından biri değildir?", options: ["مِفْعَلٌ", "مِفْعَالٌ", "مِفْعَلَةٌ", "مَفْعُولٌ"], answer: 3, why: "مَفْعُولٌ ism-i mef‘ûl kalıbıdır." },
      { q: "İsm-i âletin başındaki mîm genellikle hangi harekeyle ayırt edilir?", options: ["Üstün: مَ", "Esre: مِ", "Ötre: مُ", "Sükûn: مْ"], answer: 1, why: "Üç klasik kalıbın tamamı مِ ile başlar." }
    ]
  },
  {
    id: "fail", title: "İsm-i Fâil", subtitle: "Eylemi yapan", duration: "10 dk", level: "Temel",
    intro: "Fiildeki işi yapanı veya o niteliği taşıyanı gösterir; Türkçedeki ‘-an/-en’ yapısına yaklaşır.", goal: "Sülâsî ve mezîd fiillerde yapanı doğru türetmek",
    memory: "Üç harflide ortadaki elif yapanı ayağa kaldırır: كَتَبَ → كَاتِبٌ.",
    rule: "Sülâsî fiilden <b>فَاعِلٌ</b>. Mezîd fiilde muzâri alınır; muzâraat harfi مُ yapılır ve sondan önceki harf esrelenir: يُكْرِمُ → مُكْرِمٌ.",
    pattern: { from: "كَتَبَ", fromTr: "yazdı", to: "كَاتِبٌ", toTr: "yazan / yazar" },
    concepts: [
      { ar: "فَاعِلٌ", title: "Sülâsî fiil", text: "نَصَرَ → نَاصِرٌ; yardım eden." },
      { ar: "مُفَعِّلٌ", title: "Mezîd fiil", text: "عَلَّمَ / يُعَلِّمُ → مُعَلِّمٌ; öğreten." }
    ],
    examples: [
      { ar: "جَاءَ الْكَاتِبُ", tr: "Yazar geldi.", tag: "yapan" },
      { ar: "الطَّالِبُ حَافِظٌ دَرْسَهُ", tr: "Öğrenci dersini ezberlemiştir.", tag: "yapan" },
      { ar: "هٰذَا مُعَلِّمٌ مَاهِرٌ", tr: "Bu mahir bir öğretmendir.", tag: "mezîd" }
    ],
    questions: [
      { q: "<span class='arabic'>نَصَرَ</span> fiilinin ism-i fâili hangisidir?", options: ["نَاصِرٌ", "مَنْصُورٌ", "مِنْصَارٌ", "أَنْصَرُ"], answer: 0, why: "Sülâsî fiil فَاعِلٌ kalıbına girer: نَاصِرٌ." },
      { q: "<span class='arabic'>مُعَلِّمٌ</span> kelimesi neyi gösterir?", options: ["Öğretilen", "Öğreten", "Öğretme yeri", "Öğretme zamanı"], answer: 1, why: "عَلَّمَ fiilinin ism-i fâilidir: öğreten, öğretmen." },
      { q: "Mezîd fiilde ism-i fâil yapılırken sondan önceki harf nasıl okunur?", options: ["Üstün", "Esre", "Ötre", "Sükûn"], answer: 1, why: "Muzâraat harfi مُ yapılır, sondan önceki harf esrelenir: مُكْرِمٌ." }
    ]
  },
  {
    id: "meful", title: "İsm-i Mef‘ûl", subtitle: "Eylemden etkilenen", duration: "10 dk", level: "Temel",
    intro: "Fiilin etkilediği kişi veya nesneyi gösterir; Türkçedeki ‘-ılmış/-ilmiş’ fikrine yaklaşır.", goal: "Yapan ile yapılanı kalıp üzerinden ayırmak",
    memory: "فَاعِلٌ yapan; مَفْعُولٌ yapılan. Baştaki م ve uzayan و edilgen izi bırakır.",
    rule: "Sülâsî fiilden <b>مَفْعُولٌ</b>. Mezîd fiilde muzâri alınır; muzâraat harfi مُ yapılır ve sondan önceki harf üstünlenir: يُكْرِمُ → مُكْرَمٌ.",
    pattern: { from: "كَتَبَ", fromTr: "yazdı", to: "مَكْتُوبٌ", toTr: "yazılmış / yazılan" },
    concepts: [
      { ar: "مَفْعُولٌ", title: "Sülâsî fiil", text: "فَتَحَ → مَفْتُوحٌ; açılmış/açık." },
      { ar: "مُفَعَّلٌ", title: "Mezîd fiil", text: "عَلَّمَ / يُعَلِّمُ → مُعَلَّمٌ; öğretilmiş." }
    ],
    examples: [
      { ar: "الْبَابُ مَفْتُوحٌ", tr: "Kapı açıktır / açılmıştır.", tag: "etkilenen" },
      { ar: "قَرَأْتُ الْكِتَابَ الْمَكْتُوبَ", tr: "Yazılmış kitabı okudum.", tag: "etkilenen" },
      { ar: "الطَّالِبُ مُكَرَّمٌ", tr: "Öğrenci onurlandırılmıştır.", tag: "mezîd" }
    ],
    questions: [
      { q: "<span class='arabic'>فَتَحَ</span> fiilinin ism-i mef‘ûlü hangisidir?", options: ["فَاتِحٌ", "مِفْتَاحٌ", "مَفْتُوحٌ", "مَفْتَحٌ"], answer: 2, why: "مَفْتُوحٌ, مَفْعُولٌ kalıbında ‘açılmış’ demektir." },
      { q: "<span class='arabic'>كَاتِبٌ / مَكْتُوبٌ</span> ayrımı hangisidir?", options: ["Yer / zaman", "Yazan / yazılan", "Araç / yer", "Küçük / büyük"], answer: 1, why: "كَاتِبٌ yapanı, مَكْتُوبٌ eylemden etkileneni gösterir." },
      { q: "Mezîd fiilde ism-i mef‘ûlde sondan önceki harf nasıldır?", options: ["Esreli", "Üstünlü", "Sükûnlu", "Daima şeddeli"], answer: 1, why: "İsm-i fâilden ayıran temel işaret sondan önceki harfin üstünlü olmasıdır: مُكْرَمٌ." }
    ]
  },
  {
    id: "sinav", title: "Sınav İpuçları", subtitle: "Hızlı teşhis ve ezber", duration: "12 dk", level: "Tekrar",
    intro: "Soruda bütün kelimeyi çevirmeye çalışmak yerine önce görsel işareti, sonra kökü, en son bağlamı kontrol et.", goal: "Kalıpları 30 saniyelik teşhis yöntemiyle ayırmak",
    memory: "Kim? فَاعِل — Ne yapılmış? مَفْعُول — Neyle? مِفْعَال — Nerede/ne zaman? مَفْعَل.",
    rule: "Üç adım: <b>1) Ek harfi işaretle, 2) kökü çıkar, 3) cümleye kim/neyle/nerede/daha mı sorusunu sor.</b>",
    pattern: { from: "KÖK", fromTr: "çekirdek anlam", to: "KALIP + BAĞLAM", toTr: "sorudaki görev" },
    concepts: [
      { ar: "فَاعِلٌ ↔ مَفْعُولٌ", title: "Yapan / yapılan", text: "Ortadaki elif yapanı; مَـ ve و yapılanı hatırlatsın." },
      { ar: "مَـ ↔ مِـ", title: "Yer-zaman / araç", text: "مَ çoğu kez sahne; مِ çoğu kez araç kapısıdır." },
      { ar: "أَفْعَلُ", title: "Karşılaştırma alarmı", text: "Cümlede مِنْ görürsen ism-i tafdîli hemen kontrol et." },
      { ar: "فُعَيْلٌ", title: "Küçültme alarmı", text: "Ortadaki يْ tasğîrin güçlü parmak izidir." }
    ],
    examples: [
      { ar: "مُعَلِّمٌ / مُعَلَّمٌ", tr: "Sondan önce: esre → öğreten; üstün → öğretilen", tag: "kritik ayrım" },
      { ar: "مَفْتَحٌ / مِفْتَاحٌ", tr: "مَ → yer/zaman; مِ → araç", tag: "kritik ayrım" },
      { ar: "أَكْبَرُ مِنْ", tr: "مِنْ görünce ‘daha ...’ karşılaştırmasını ara", tag: "hızlı ipucu" }
    ],
    questions: [
      { q: "Soruda <span class='arabic'>مِنْ</span> ile birlikte <span class='arabic'>أَفْعَلُ</span> görürsen ilk şüphen ne olmalı?", options: ["İsm-i âlet", "İsm-i tafdîl", "Mastar-ı mimî", "İsm-i tasğîr"], answer: 1, why: "أَفْعَلُ + مِنْ, karşılaştırma yapısının en hızlı işaretidir." },
      { q: "<span class='arabic'>مُكْرِمٌ / مُكْرَمٌ</span> çiftini en hızlı ne ayırır?", options: ["İlk harf", "Son harf", "Sondan önceki harfin esre/üstünü", "Harf sayısı"], answer: 2, why: "مُكْرِمٌ yapan; مُكْرَمٌ yapılan. Kritik fark sondan önceki harekedir." },
      { q: "Bilinmeyen bir kelimede en verimli çözüm sırası hangisidir?", options: ["Çeviri → tahmin → kök", "Ek/kalıp → kök → bağlam", "Bağlam → ezber → harf sayısı", "Yalnız sözlük anlamı"], answer: 1, why: "Önce biçimsel işareti, sonra kökü, en son cümledeki görevi kontrol etmek hatayı azaltır." }
    ]
  }
];

const TOPIC_DETAILS = {
  zaman: {
    narrative: "İsm-i zaman, fiilin kendisini çekmek yerine o fiilin gerçekleştiği vakti bir isim hâline getirir. Örneğin وَعَدَ ‘söz verdi’ bir olaydır; مَوْعِدٌ ise o sözün yerine getirileceği belirli vakittir. Bu yüzden ism-i zaman cümlede isim gibi davranır: ال alabilir, tamlama kurabilir ve cer harfinden sonra gelebilir.",
    process: [
      { title: "Kökü bul", text: "مَوْعِدٌ kelimesinde ek olan م harfini ayır; geriye و–ع–د kökü kalır." },
      { title: "Fiil ailesini kontrol et", text: "Sülâsî fiillerde مَفْعَلٌ ve مَفْعِلٌ seçeneklerini; mezîd fiillerde muzâri temelli kalıbı düşün." },
      { title: "Bağlama zaman sorusu sor", text: "Kelime ‘ne zaman?’ sorusuna cevap veriyorsa ism-i zamandır: مَوْعِدُ الدَّرْسِ = dersin vakti." }
    ],
    pitfalls: ["مَفْعَل / مَفْعِل görünce otomatik olarak ‘yer’ deme; aynı biçim zaman da bildirebilir.", "Kalıp güçlü bir ipucudur fakat sözlükleşmiş kelimelerin anlamı kök anlamından genişleyebilir."],
    exampleNote: "مَغْرِبٌ tek başına hem batış yeri hem batış zamanı çağrıştırabilir. الشَّمْسِ ile kurduğu tamlama ve cümlenin bütünü doğru anlamı seçtirir."
  },
  mekan: {
    narrative: "İsm-i mekân, bir eylemin sahnesini adlandırır. مَكْتَبٌ kelimesini yalnız ‘ofis’ diye ezberlemek yerine كَتَبَ fiiliyle bağlarsan yapıyı görürsün: yazma işinin yapıldığı yer. Böylece daha önce karşılaşmadığın مَدْخَلٌ ve مَخْرَجٌ gibi kelimeleri de köklerinden tahmin edebilirsin.",
    process: [
      { title: "Baştaki مَ işaretini tara", text: "Bu işaret yer/zaman ailesi için ilk alarmdır; tek başına kesin hüküm değildir." },
      { title: "Kök fiili geri kur", text: "مَدْخَلٌ → دَخَلَ ‘girdi’; مَخْرَجٌ → خَرَجَ ‘çıktı’." },
      { title: "‘Nerede?’ ile doğrula", text: "Giriş yeri, çıkış yeri, oyun yeri gibi bir mekân cevabı veriyorsa teşhis tamamlanır." }
    ],
    pitfalls: ["مَكْتَبٌ ile مِكْتَبٌ aynı değildir; baştaki mîmin harekesi kalıp ailesini değiştirir.", "Yer ismi ile mastar-ı mimî biçimce çakışabilir; cümlede yer mi olay mı anlatıldığına bak."],
    exampleNote: "هٰذَا مَدْخَلُ الْمَدْرَسَةِ cümlesinde مَدْخَلُ, ‘girme eylemi’ değil okulun fiziksel giriş noktasını gösterir."
  },
  tafdil: {
    narrative: "İsm-i tafdîl ortak bir niteliği iki taraf arasında ölçer. أَكْبَرُ derken iki varlık da büyüklük niteliğine sahiptir; biri diğerinden daha fazlasını taşır. Aynı kelime yapı değişince ‘daha büyük’ veya ‘en büyük’ diye çevrilebilir.",
    process: [
      { title: "أَفْعَلُ kalıbını tanı", text: "أَكْبَرُ، أَصْغَرُ، أَفْضَلُ gibi kelimelerde ortak dış yapıyı gör." },
      { title: "مِنْ var mı bak", text: "Ardından مِنْ ve ikinci taraf geliyorsa karşılaştırma yap: أَكْبَرُ مِنْ = …den daha büyük." },
      { title: "ال veya tamlamayı kontrol et", text: "الْأَكْبَرُ ya da أَفْضَلُ كِتَابٍ gibi yapılar çoğunlukla ‘en’ anlamı verir." }
    ],
    pitfalls: ["Her أَفْعَلُ görünüşlü kelime ism-i tafdîl değildir; bazı renk ve kusur sıfatları da bu kalıptadır.", "مِنْ ile gelen karşılaştırmada ism-i tafdîl genellikle cinsiyet ve sayı bakımından değişmeden tekil müzekker görünümünü korur."],
    exampleNote: "عَلِيٌّ أَطْوَلُ مِنْ حَسَنٍ yapısında Ali ölçülen, أَطْوَلُ ortak özellik, مِنْ حَسَنٍ ise karşılaştırma ölçütüdür."
  },
  tasgir: {
    narrative: "Tasğîr yalnız bir nesneyi fiziksel olarak küçültmez. Konuşanın nesneye bakışını da taşıyabilir: sevgi, şefkat, azımsama veya yakınlık. Bu nedenle doğru Türkçe karşılık bazen ‘küçük’, bazen ‘-cık/-ceğiz’ olur.",
    process: [
      { title: "Asıl ismi yalınlaştır", text: "Kelimenin ال takısını ve çekim eklerini kaldır; kök/gövde harflerini belirle." },
      { title: "İlk harfi ötrele", text: "Tasğîr ailesinin başlangıç sesi çoğunlukla فُـ görünümündedir." },
      { title: "İkinci harften sonra يْ getir", text: "جَبَلٌ → جُبَيْلٌ örneğindeki يْ, kalıbın en kolay seçilen izidir." }
    ],
    pitfalls: ["Kelimedeki her يْ tasğîr değildir; kelimenin aslı ve anlamı birlikte kontrol edilmelidir.", "Dört ve beş harfli isimlerde yalnız فُعَيْلٌ ezberine dayanma; harf sayısına göre kalıp genişler."],
    exampleNote: "يَا بُنَيَّ ifadesinde amaç oğlun fiziksel küçüklüğünü bildirmekten çok şefkatli bir hitap kurmaktır: ‘oğulcuğum’."
  },
  turemis: {
    narrative: "Mezîd fiillerde kökün temel anlamı korunur, fakat sahnedeki katılımcılar veya eylemin yönü değişir. عَلِمَ ‘bildi’ iken عَلَّمَ ‘bir başkasının bilmesini sağladı’, تَعَلَّمَ ise ‘bilgiyi kendisi edindi’ olur. Bâbı, köke eklenen bir anlam merceği gibi düşün.",
    process: [
      { title: "Asıl üç harfi işaretle", text: "اِسْتَغْفَرَ içinde ekler ا–س–ت; kök غ–ف–ر’dir." },
      { title: "Ek harfleri kalıpla eşleştir", text: "Şedde II. bâbı, baştaki تـ V/VI. bâbı, استـ ise X. bâbı düşündürür." },
      { title: "Anlam eğilimini bağlamda dene", text: "Ettirme, karşılıklılık, dönüşlülük veya isteme fikrinden hangisi cümleye uyuyor kontrol et." }
    ],
    pitfalls: ["Bâb anlamlarını matematik formülü gibi uygulama; bunlar eğilimdir ve fiilin sözlük anlamı son sözü söyler.", "Ek harf sandığın harf kökün parçası olabilir. Önce güvenilir biçimde kökü belirle."],
    exampleNote: "عَلَّمَ cümlesinde öğretmen özne, öğrenci nesnedir; تَعَلَّمَ cümlesinde öğrenci artık öğrenme sürecinin öznesidir. Bâb, rollerin dağılımını değiştirmiştir."
  },
  mastar: {
    narrative: "Mastar, fiilin bildirdiği olayı zaman çizgisinden çıkarıp bir kavrama dönüştürür. كَتَبَ ‘yazdı’ dediğinde geçmişteki bir olay ve gizli bir özne vardır. كِتَابَةٌ ‘yazma’ dediğinde ise yalnız eylemin adı kalır; bu ad cümlenin öznesi veya nesnesi olabilir.",
    process: [
      { title: "Zaman ve şahsı kaldır", text: "‘Kim yaptı, ne zaman yaptı?’ bilgisi yoksa ve eylem adlandırılıyorsa mastar ihtimali güçlenir." },
      { title: "Fiille çift hâlinde öğren", text: "Özellikle sülâsî fiili mastarıyla kaydet: خَرَجَ – خُرُوجٌ." },
      { title: "Cümlede isim görevini bul", text: "أُحِبُّ الْقِرَاءَةَ içinde الْقِرَاءَةَ, sevme fiilinin nesnesidir." }
    ],
    pitfalls: ["Türkçede mastarı her zaman ‘-mak/-mek’ ile çevirmek doğal olmayabilir; ‘okuma, çıkış, anlayış’ da doğru olabilir.", "Sülâsî mastarlar için tek ve şaşmaz bir vezin arama; büyük bölümü semâîdir."],
    exampleNote: "طَلَبُ الْعِلْمِ مُهِمٌّ cümlesinde طَلَبُ tamlamanın başıdır ve bütün ‘ilim talep etme’ grubu cümlenin öznesidir."
  },
  "mastar-turleri": {
    narrative: "Mastar türleri aynı eylemi farklı bir kamerayla gösterir. Aslî mastar olayın adını, merre kaç kez gerçekleştiğini, hey’et nasıl gerçekleştiğini, mimî ise eylemi م ile başlayan isimleşmiş bir biçimde sunar. Sınâî mastar ise bir isim veya sıfattan soyut kavram üretir.",
    process: [
      { title: "Soruyu belirle", text: "Olayın kendisi mi, bir kez oluşu mu, yapılış biçimi mi, yoksa soyut bir nitelik mi anlatılıyor?" },
      { title: "Biçim işaretini bul", text: "Merrede çoğunlukla فَعْلَةٌ; hey’ette فِعْلَةٌ; sınâîde ـِيَّة görülür." },
      { title: "Bağlamla son kararı ver", text: "Aynı yazılış bazı fiillerde merre ve hey’et arasında bağlama göre yorumlanabilir." }
    ],
    pitfalls: ["Sonunda ة bulunan her mastarı ‘bir kez’ diye etiketleme; kelimenin aslî mastarı zaten ة ile bitebilir.", "Mastar-ı mimî, ism-i zaman ve ism-i mekânla aynı görünebilir; anlam görevini cümleden çıkar."],
    exampleNote: "جَلَسَ جِلْسَةَ الْعَالِمِ ifadesinde sayı değil nitelik önemlidir: ‘âlimin oturuş biçimi gibi’. Bu yüzden hey’et mastarıdır."
  },
  alet: {
    narrative: "İsm-i âlet, fiilin faili veya nesnesi değil, eylemi gerçekleştirmeye yarayan aracı adlandırır. مِفْتَاحٌ kelimesinde ف–ت–ح kökü ‘açma’ fikrini, مِفْعَالٌ kalıbı ise bu iş için kullanılan aracı taşır.",
    process: [
      { title: "Baştaki مِ sesini fark et", text: "مِفْعَلٌ، مِفْعَالٌ ve مِفْعَلَةٌ kalıplarının ortak başlangıcıdır." },
      { title: "Kök eylemi çıkar", text: "مِكْنَسَةٌ → كَنَسَ ‘süpürdü’; مِنْشَارٌ → نَشَرَ ‘kesti/yaydı’." },
      { title: "‘Neyle?’ sorusunu sor", text: "Kelime eylemin gerçekleştirildiği gereci karşılıyorsa araç adı teşhisi güçlenir." }
    ],
    pitfalls: ["Bu üç vezne teorik olarak her fiili sokup yeni araç adı üretme; klasik araç adlarının önemli kısmı semâîdir.", "مِـ ile başlayan her sözlük kelimesi ism-i âlet değildir; kök-anlam ilişkisini doğrula."],
    exampleNote: "فَتَحْتُ الْبَابَ بِالْمِفْتَاحِ cümlesindeki ب harf-i cerri ‘ile’ anlamı verir ve مِفْتَاحِ kelimesinin araç görevini açıkça gösterir."
  },
  fail: {
    narrative: "İsm-i fâil, fiilin yapanını isimleştirir; ancak yalnız meslek adı değildir. Geçici bir eylemi yapanı da kalıcı bir niteliği taşıyanı da anlatabilir. كَاتِبٌ bağlama göre ‘yazan kişi’, ‘yazar’ veya ‘yazmakta olan’ diye çevrilebilir.",
    process: [
      { title: "Fiil sülâsî mi bak", text: "Üç harfliyse kökü فَاعِلٌ kalıbına yerleştir: ك–ت–ب → كَاتِبٌ." },
      { title: "Mezîdse muzâriyi getir", text: "يُعَلِّمُ biçimini temel al; baştaki muzâraat harfini مُ ile değiştir." },
      { title: "Sondan öncekini esrele", text: "يُعَلِّمُ → مُعَلِّمٌ. Esre, mezîd ism-i fâilin kritik işaretidir." }
    ],
    pitfalls: ["فَاعِلٌ kalıbındaki kelime her zaman o anda yapılan işi anlatmaz; sözlükleşmiş meslek ve sıfat olabilir.", "Nâkıs, ecvef ve mehmûz fiillerde ses/harf değişimleri görülür; yalnız sağlam fiil şablonunu zorla uygulama."],
    exampleNote: "الطَّالِبُ حَافِظٌ دَرْسَهُ cümlesinde حَافِظٌ yapanı gösterir; دَرْسَهُ ise bu eylemin üzerinde gerçekleştiği unsurdur."
  },
  meful: {
    narrative: "İsm-i mef‘ûl, eylemi yapanı değil eylemin üzerine yöneldiği unsuru gösterir. مَكْتُوبٌ kelimesi ‘birinin yazdığı şey’dir; yazanın kim olduğu söylenmese de yazma eyleminin izi nesnenin üzerindedir.",
    process: [
      { title: "Sülâsîde مَفْعُولٌ kur", text: "Kök harflerini sırayla yerleştir: ك–ت–ب → مَكْتُوبٌ." },
      { title: "Mezîdde muzâriyi getir", text: "يُكْرِمُ biçimindeki muzâraat harfini مُ yap." },
      { title: "Sondan öncekini üstünle", text: "مُكْرِمٌ yapan iken مُكْرَمٌ yapılan/onurlandırılandır." }
    ],
    pitfalls: ["Lâzım fiiller doğrudan nesne almadığı için her fiilden aynı rahatlıkla ism-i mef‘ûl beklenmez.", "مَفْعُولٌ görünüşlü bazı kelimeler sözlükte özel anlam kazanmış olabilir; cümledeki görevini yine kontrol et."],
    exampleNote: "الْبَابُ مَفْتُوحٌ cümlesinde kapı eylemi yapan değildir; açma eyleminin sonucunu taşıdığı için مَفْتُوحٌ kullanılır."
  },
  sinav: {
    narrative: "Sınavda başarı çoğu zaman bütün cümleyi kusursuz çevirmekten değil, kalıpları hızlı elemekten gelir. Kelimenin ek harflerini renkli bir kalemle ayırıyormuş gibi zihninde işaretle. Sonra kökü ve cümlede cevap verdiği soruyu bul.",
    process: [
      { title: "Dış kabuğu tara", text: "مَـ, مِـ, مُـ, أَـ, ortadaki ا veya يْ gibi yüksek değerli işaretleri bul." },
      { title: "İki aday bırak", text: "Örneğin مَفْعَلٌ için yer ve zaman adaylarını tut; diğer seçenekleri ele." },
      { title: "Bağlam sorusuyla bitir", text: "Nerede/ne zaman, kim/ne yapılmış, neyle veya daha mı sorularından uygun olanı uygula." }
    ],
    pitfalls: ["Yalnız Türkçe karşılığı ezberlemek benzer kalıplı yeni kelimelerde işe yaramaz; biçim-anlam bağını kur.", "İlk gördüğün م harfine dayanarak karar verme; harekesi ve kelimenin geri kalan kalıbı belirleyicidir."],
    exampleNote: "مُعَلِّمٌ ve مُعَلَّمٌ aynı harfleri taşır. Sorunun ölçtüğü şey çoğu zaman tek bir harekedir: sondan önce esre yapanı, üstün yapılanı gösterir."
  }
};

TOPICS.forEach(topic => Object.assign(topic, TOPIC_DETAILS[topic.id]));

const EXAM_QUESTIONS = TOPICS.flatMap(topic =>
  topic.questions.slice(0, 1).map(question => ({ ...question, topic: topic.title }))
);
