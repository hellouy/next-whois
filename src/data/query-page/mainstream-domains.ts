export const MAINSTREAM_DOMAINS = new Set<string>([
  "google.com","bing.com","baidu.com","yahoo.com","yandex.com","duckduckgo.com","sogou.com","so.com","360.com",
  // Social
  "facebook.com","instagram.com","twitter.com","x.com","tiktok.com","linkedin.com","reddit.com","pinterest.com",
  "snapchat.com","weibo.com","qq.com","douyin.com","bilibili.com","zhihu.com","xiaohongshu.com","tieba.baidu.com",
  "tumblr.com","flickr.com","quora.com","discord.com","telegram.org","line.me","kakaotalk.com","vk.com",
  // Video
  "youtube.com","netflix.com","twitch.tv","hulu.com","vimeo.com","youku.com","iqiyi.com","v.qq.com","mango.tv",
  "disneyplus.com","primevideo.com","hbomax.com","crunchyroll.com","niconico.jp","dailymotion.com",
  // E-commerce
  "amazon.com","ebay.com","taobao.com","tmall.com","jd.com","aliexpress.com","shopify.com","etsy.com",
  "walmart.com","costco.com","target.com","rakuten.com","lazada.com","shopee.com","pinduoduo.com","wish.com",
  "zalando.com","flipkart.com","mercadolibre.com","mercadolibre.com.ar",
  // Tech
  "microsoft.com","apple.com","github.com","stackoverflow.com","cloudflare.com","adobe.com","oracle.com",
  "ibm.com","intel.com","nvidia.com","amd.com","openai.com","anthropic.com","huggingface.co","deepmind.com",
  "samsung.com","sony.com","lg.com","xiaomi.com","huawei.com","lenovo.com","dell.com","hp.com","asus.com",
  // Cloud/Dev
  "aws.amazon.com","digitalocean.com","heroku.com","netlify.com","vercel.com","railway.app","render.com",
  "npmjs.com","pypi.org","docker.com","kubernetes.io","linux.org","debian.org","ubuntu.com","archlinux.org",
  // Productivity/SaaS
  "dropbox.com","slack.com","zoom.us","notion.so","figma.com","canva.com","trello.com","asana.com",
  "atlassian.com","confluence.com","jira.atlassian.com","hubspot.com","salesforce.com","servicenow.com",
  "office.com","google.com","docs.google.com","drive.google.com","mail.google.com",
  // Finance
  "paypal.com","stripe.com","visa.com","mastercard.com","americanexpress.com","chase.com","wellsfargo.com",
  "bankofamerica.com","citibank.com","hsbc.com","alipay.com","wechatpay.com","patreon.com",
  // Media/News
  "bbc.com","cnn.com","nytimes.com","theguardian.com","reuters.com","bloomberg.com","ap.org",
  "xinhua.net","people.com.cn","sina.com.cn","163.com","sohu.com","ifeng.com","thepaper.cn",
  "wsj.com","ft.com","forbes.com","businessinsider.com","techcrunch.com","theverge.com","wired.com",
  // Lifestyle/Travel
  "airbnb.com","booking.com","tripadvisor.com","expedia.com","uber.com","lyft.com","doordash.com",
  "grubhub.com","yelp.com","zomato.com","swiggy.com","meituan.com","eleme.cn",
  // Music/Streaming
  "spotify.com","apple.com","pandora.com","soundcloud.com","tidal.com","deezer.com","qqmusic.qq.com",
  "netease.com","163.com",
  // Domain/Web infra
  "godaddy.com","namecheap.com","dynadot.com","name.com","porkbun.com","cloudflare.com","letsencrypt.org",
  "wordpress.com","wix.com","squarespace.com","webflow.com",
  // Knowledge
  "wikipedia.org","medium.com","substack.com","google.com",
  // Crypto
  "coinbase.com","binance.com","kraken.com","okx.com","bybit.com","metamask.io","etherscan.io",
  // Gaming
  "steam.com","steampowered.com","epicgames.com","ea.com","blizzard.com","roblox.com","minecraft.net",
  "nintendo.com","playstation.com","xbox.com",
  // Education
  "coursera.org","udemy.com","edx.org","khanacademy.org","duolingo.com","academia.edu","researchgate.net",
  "mit.edu","harvard.edu","stanford.edu","ox.ac.uk","cam.ac.uk",
  // Gov/Standards
  "iana.org","icann.org","w3.org","ietf.org","iso.org",
  // CN Mainstream (国内知名站点)
  "douban.com","kuaishou.com","douyu.com","huya.com","ximalaya.com","hupu.com","dianping.com",
  "ctrip.com","qunar.com","feizhu.com","12306.cn","suning.com","vip.com","dangdang.com",
  "58.com","toutiao.com","csdn.net","juejin.cn","36kr.com","tianyancha.com","qcc.com",
  "maimai.cn","zhipin.com","51job.com","zhaopin.com","liepin.com","weixin.qq.com","cctv.com",
  "mgtv.com","didichuxing.com","lianjia.com","ke.com","autohome.com.cn","xueqiu.com","eastmoney.com",
  "10jqka.com.cn","futunn.com","tigerbrokers.com",
  // Global Tech (全球科技/互联网补漏)
  "meta.com","spacex.com","tesla.com","qualcomm.com","mediatek.com","tsmc.com","arm.com","sap.com",
  "workday.com","jetbrains.com","gitlab.com","bitbucket.org","mongodb.com","redis.com","postgresql.org",
  "mysql.com","elastic.co","snowflake.com","datadoghq.com","grafana.com","twilio.com","sendgrid.com",
  "mailchimp.com","zendesk.com","intercom.com","okta.com","auth0.com","zapier.com","airtable.com",
  "monday.com","clickup.com","linear.app","wikimedia.org","kernel.org","python.org","nodejs.org",
  "golang.org","rust-lang.org","swift.org","java.com","spring.io",
  // Gov/Public service (政府/公共服务)
  "gov.cn","un.org","who.int","unicef.org","unesco.org","worldbank.org","imf.org","oecd.org",
  "wto.org","redcross.org","fao.org","undp.org","nato.int","whitehouse.gov","gov.uk","go.jp",
  // Banking/Finance (金融/支付/银行)
  "icbc.com.cn","ccb.com","abchina.com","boc.cn","cmbchina.com","bankcomm.com","spdb.com.cn",
  "cib.com.cn","cebbank.com","cmbc.com.cn","ecitic.com","cgbchina.com.cn","psbc.com","unionpay.com",
  "antgroup.com","jpmorgan.com","goldmansachs.com","morganstanley.com","ubs.com","barclays.com",
  "deutsche-bank.de","schwab.com","fidelity.com","vanguard.com","blackrock.com","robinhood.com",
  "revolut.com","wise.com","squareup.com",
  // Universities (大学/教育机构)
  "tsinghua.edu.cn","pku.edu.cn","fudan.edu.cn","sjtu.edu.cn","zju.edu.cn","ustc.edu.cn","nju.edu.cn",
  "whu.edu.cn","hit.edu.cn","ruc.edu.cn","princeton.edu","yale.edu","caltech.edu","berkeley.edu",
  "columbia.edu","uchicago.edu","cornell.edu","upenn.edu","duke.edu","northwestern.edu","ucla.edu",
  "cmu.edu","imperial.ac.uk","lse.ac.uk","ucl.ac.uk","ethz.ch","nus.edu.sg","ntu.edu.sg","hku.hk",
  "cuhk.edu.hk","ust.hk",
  // AI/Frontier (AI 前沿)
  "x.ai","midjourney.com","character.ai","perplexity.ai","stability.ai","groq.com","cohere.com",
  "mistral.ai","deepseek.com","moonshot.cn","zhipuai.cn","doubao.com","aliyun.com","iflytek.com",
  "minimaxi.com",
  // CN Brands (国内知名品牌)
  "oppo.com","vivo.com","oneplus.com","honor.com","zte.com.cn","tcl.com","hisense.com","skyworth.com",
  "konka.com","xiaopeng.com","nio.com","lixiang.com","byd.com","geely.com","gwm.com.cn","leapmotor.com",
  "caocao.com","dongqiudi.com","tianya.cn","qingting.fm","dedao.cn","dewu.com","smzdm.com","mogujie.com",
  "you.163.com","dingtalk.com","feishu.cn","wps.cn","shimo.im","yuque.com","docs.qq.com","qyer.com",
  "mafengwo.cn","tongcheng.com","pingan.com","webank.com","mybank.cn","lu.com","hxb.com.cn",
  "fanqienovel.com","qidian.com","yuewen.com","jjwxc.net","temu.com","shein.com","1688.com","alibaba.com",
  "cainiao.com","sf-express.com","zto.com",
  // Gov Ministries (政务部委)
  "miit.gov.cn","moe.gov.cn","mof.gov.cn","mps.gov.cn","nhc.gov.cn","samr.gov.cn","ndrc.gov.cn",
  "mofcom.gov.cn","mfa.gov.cn","pbc.gov.cn","csrc.gov.cn","cbirc.gov.cn","nfra.gov.cn","customs.gov.cn",
  "nrta.gov.cn","nmpa.gov.cn","most.gov.cn","moj.gov.cn","court.gov.cn",
  // Gov/Intl orgs (国际政府与组织)
  "europa.eu","usa.gov","state.gov","india.gov.in","canada.ca","korea.go.kr","gov.sg","msf.org",
  "greenpeace.org","amnesty.org","unhcr.org","ilo.org",
  // More Universities (更多高校)
  "tongji.edu.cn","buaa.edu.cn","bit.edu.cn","xjtu.edu.cn","scu.edu.cn","sysu.edu.cn","nankai.edu.cn",
  "tju.edu.cn","xmu.edu.cn","sdu.edu.cn","jlu.edu.cn","hust.edu.cn","csu.edu.cn","hnu.edu.cn",
  "seu.edu.cn","scut.edu.cn","uestc.edu.cn","bupt.edu.cn","u-tokyo.ac.jp","kyoto-u.ac.jp","snu.ac.kr",
  "kaist.ac.kr","unimelb.edu.au","usyd.edu.au","monash.edu","utoronto.ca","ubc.ca","mcgill.ca",
  "nyu.edu","dartmouth.edu",
  // Global companies (全球企业)
  "databricks.com","palantir.com","crowdstrike.com","signal.org","proton.me","cgtn.com","aljazeera.com",
  "dw.com","npr.org","economist.com","time.com","fortune.com","nationalgeographic.com","riotgames.com",
  "supercell.com","toyota.com","honda.com","nissan.com","hyundai.com","kia.com","vw.com","bmw.com",
  "mercedes-benz.com","audi.com","ford.com","gm.com","porsche.com","nike.com","adidas.com",
  "mcdonalds.com","starbucks.com","coca-cola.com","nestle.com","pg.com","unilever.com","siemens.com",
  "ge.com","3m.com","boeing.com","airbus.com","shell.com","bp.com","cnpc.com.cn","sinopec.com",
  "10086.cn","chinaunicom.com.cn","chinatelecom.com.cn","att.com","verizon.com","t-mobile.com",
  "dhl.com","fedex.com","ups.com",
]);
