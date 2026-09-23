/**
 * Chinese pinyin data for domain value scoring.
 *
 * PINYIN_SYLLABLES — the valid toneless Mandarin syllables (Hanyu Pinyin).
 * PINYIN_WORDS     — curated common two-syllable (shuangpin) words that are
 *                    frequently used in Chinese domain investing.
 *
 * Hand-maintained data file. Keep entries lowercase ASCII.
 */

export const PINYIN_SYLLABLES: ReadonlySet<string> = new Set([
  "a", "ai", "an", "ang", "ao",
  "ba", "bai", "ban", "bang", "bao", "bei", "ben", "beng", "bi", "bian", "biao", "bie", "bin", "bing", "bo", "bu",
  "ca", "cai", "can", "cang", "cao", "ce", "cen", "ceng", "cha", "chai", "chan", "chang", "chao", "che", "chen", "cheng", "chi", "chong", "chou", "chu", "chua", "chuai", "chuan", "chuang", "chui", "chun", "chuo", "ci", "cong", "cou", "cu", "cuan", "cui", "cun", "cuo",
  "da", "dai", "dan", "dang", "dao", "de", "dei", "deng", "di", "dian", "diao", "die", "ding", "diu", "dong", "dou", "du", "duan", "dui", "dun", "duo",
  "e", "ei", "en", "eng", "er",
  "fa", "fan", "fang", "fei", "fen", "feng", "fo", "fou", "fu",
  "ga", "gai", "gan", "gang", "gao", "ge", "gei", "gen", "geng", "gong", "gou", "gu", "gua", "guai", "guan", "guang", "gui", "gun", "guo",
  "ha", "hai", "han", "hang", "hao", "he", "hei", "hen", "heng", "hong", "hou", "hu", "hua", "huai", "huan", "huang", "hui", "hun", "huo",
  "ji", "jia", "jian", "jiang", "jiao", "jie", "jin", "jing", "jiong", "jiu", "ju", "juan", "jue", "jun",
  "ka", "kai", "kan", "kang", "kao", "ke", "ken", "keng", "kong", "kou", "ku", "kua", "kuai", "kuan", "kuang", "kui", "kun", "kuo",
  "la", "lai", "lan", "lang", "lao", "le", "lei", "leng", "li", "lia", "lian", "liang", "liao", "lie", "lin", "ling", "liu", "lo", "long", "lou", "lu", "luan", "lun", "luo", "lv", "lve",
  "ma", "mai", "man", "mang", "mao", "me", "mei", "men", "meng", "mi", "mian", "miao", "mie", "min", "ming", "miu", "mo", "mou", "mu",
  "na", "nai", "nan", "nang", "nao", "ne", "nei", "nen", "neng", "ni", "nian", "niang", "niao", "nie", "nin", "ning", "niu", "nong", "nou", "nu", "nuan", "nuo", "nv", "nve",
  "o", "ou",
  "pa", "pai", "pan", "pang", "pao", "pei", "pen", "peng", "pi", "pian", "piao", "pie", "pin", "ping", "po", "pou", "pu",
  "qi", "qia", "qian", "qiang", "qiao", "qie", "qin", "qing", "qiong", "qiu", "qu", "quan", "que", "qun",
  "ran", "rang", "rao", "re", "ren", "reng", "ri", "rong", "rou", "ru", "rua", "ruan", "rui", "run", "ruo",
  "sa", "sai", "san", "sang", "sao", "se", "sen", "seng", "sha", "shai", "shan", "shang", "shao", "she", "shen", "sheng", "shi", "shou", "shu", "shua", "shuai", "shuan", "shuang", "shui", "shun", "shuo", "si", "song", "sou", "su", "suan", "sui", "sun", "suo",
  "ta", "tai", "tan", "tang", "tao", "te", "teng", "ti", "tian", "tiao", "tie", "ting", "tong", "tou", "tu", "tuan", "tui", "tun", "tuo",
  "wa", "wai", "wan", "wang", "wei", "wen", "weng", "wo", "wu",
  "xi", "xia", "xian", "xiang", "xiao", "xie", "xin", "xing", "xiong", "xiu", "xu", "xuan", "xue", "xun",
  "ya", "yan", "yang", "yao", "ye", "yi", "yin", "ying", "yo", "yong", "you", "yu", "yuan", "yue", "yun",
  "za", "zai", "zan", "zang", "zao", "ze", "zei", "zen", "zeng", "zha", "zhai", "zhan", "zhang", "zhao", "zhe", "zhei", "zhen", "zheng", "zhi", "zhong", "zhou", "zhu", "zhua", "zhuai", "zhuan", "zhuang", "zhui", "zhun", "zhuo", "zi", "zong", "zou", "zu", "zuan", "zui", "zun", "zuo",
]);

export const PINYIN_WORDS: ReadonlySet<string> = new Set([
  // Technology / internet
  "keji", "wangluo", "shuju", "yunjisuan", "ruanjian", "yingyong", "xiazai", "gongju",
  "daohang", "ditu", "fanyi", "cidian", "sousuo", "liulan", "liulanqi", "wangzhan",
  "wangye", "zhuye", "kongjian", "zhuce", "denglu", "zhineng", "rengong", "jiqiren",
  "qukuai", "shuzi", "shuma", "diannao", "shouji", "dianzi", "dianqi", "xinpian",
  "suanfa", "chengxu", "kaifa", "ceshi", "yunwei", "fuwuqi", "shujuku", "jiekou",
  // Business / commerce
  "gongsi", "qiye", "shangcheng", "shangwu", "shangjia", "shangye", "maoyi", "caigou",
  "xiaoshou", "shichang", "jingji", "caijing", "jinrong", "licai", "touzi", "yinhang",
  "zhifu", "jiaoyi", "gupiao", "jijin", "daikuan", "baoxian", "zhengquan", "waihui",
  "caifu", "zijin", "rongzi", "shuiwu", "kuaiji", "shenji", "zhaoshang", "daili",
  "jiameng", "pifa", "lingshou", "gongying", "wuliu", "kuaidi", "yunshu", "cangchu",
  "peisong", "dingdan", "kucun", "caiwu", "hetong", "fapiao", "zulin", "ershou",
  // Consumer / lifestyle
  "shenghuo", "jiankang", "yiliao", "yiyao", "yisheng", "yiyuan", "meishi", "canyin",
  "lvyou", "lvxing", "jiudian", "jiaoyu", "xuexi", "peixun", "yule", "youxi", "yinyue",
  "shipin", "tupian", "zhaopian", "dianying", "dianshi", "dongman", "manhua", "xiaoshuo",
  "yuedu", "shuji", "sheying", "yishu", "meishu", "chuangyi", "guanggao", "yingxiao",
  "tuiguang", "pinpai", "fuzhuang", "shishang", "meizhuang", "huazhuang", "shoushi",
  "tiyu", "jianshen", "yundong", "saishi", "muying", "yuer", "baobao", "ertong",
  "chongwu", "shuiguo", "shucai", "lingshi", "yinliao", "meijiu", "kafei",
  // Services
  "fuwu", "kefu", "zixun", "weixiu", "anquan", "fanghu", "falv", "lvshi", "susong",
  "zhaopin", "qiuzhi", "rencai", "jianli", "peixun", "jiaoyou", "hunlian", "xiangqin",
  "shejiao", "liaotian", "pengyou", "jiaotong", "chuxing", "dache", "gongjiao",
  "fangchan", "dichan", "loupan", "zufang", "maifang", "jiancai", "zhuangxiu", "jiaju",
  "jianzhu", "sheji", "huanbao", "nengyuan", "dianli", "taiyang",
  // News / media
  "xinwen", "zixun", "meiti", "baozhi", "zazhi", "zhibo", "duanpian", "pindao",
  // Brands / platforms
  "weixin", "taobao", "jingdong", "baidu", "tengxun", "zhifubao", "douyin", "kuaishou",
  "xiaohongshu", "meituan", "pinduoduo", "bilibili", "zhihu", "weibo",
  // Cities / regions
  "beijing", "shanghai", "guangzhou", "shenzhen", "hangzhou", "chengdu", "nanjing",
  "wuhan", "tianjin", "chongqing", "xian", "suzhou", "qingdao", "changsha", "zhengzhou",
  "zhongguo", "huaxia", "zhonghua", "diyu", "chengshi",
  // Generic value words
  "mianfei", "youhui", "tejia", "zhekou", "gouwu", "dianshang", "jifen", "huiyuan",
  "chongzhi", "jiangpin", "hongbao", "paihang", "tuijian", "remen", "jingpin", "zhaopin",
]);
