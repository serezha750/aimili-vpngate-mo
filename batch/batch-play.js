#!/usr/bin/env node

const { chromium } = require('playwright');
const fs = require('fs');
const axios = require('axios');
const randomUseragent = require('random-useragent');
const { timezones } = require('timezone-list');
const { SocksProxyAgent } = require('socks-proxy-agent');

// ================== 配置区 ==================
const TARGET_URL = 'https://bysedikamoum.com/d/eyir10o51knt';
const PLAY_WAIT_SECONDS = 5;
const AD_WAIT_SECONDS = 10;
const AD_POPUP_TIMEOUT = 5000;
const LOOP_INTERVAL_SECONDS = 60;
const MAX_CONCURRENT = 3;
const MAX_IP_RETRY = 3;

const AIMILIVPN_BASE = process.env.AIMILIVPN_BASE || 'http://136.248.242.169:8787/Tp2p7wg1KVtf';
const AIMILIVPN_USER = process.env.AIMILIVPN_USER || '520878';
const AIMILIVPN_PASS = process.env.AIMILIVPN_PASS || '520878';
const AIMILIVPN_PROXY_HOST = process.env.AIMILIVPN_PROXY_HOST || (() => {
  try {
    const url = new URL(AIMILIVPN_BASE);
    return url.hostname;
  } catch { return '127.0.0.1'; }
})();

let cookieJar = '';
let proxyPortBase = 17928;

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ---------- API 封装（同上） ----------
async function loginAimili() {
  try {
    const res = await axios.post(`${AIMILIVPN_BASE}/api/login`, {
      username: AIMILIVPN_USER,
      password: AIMILIVPN_PASS
    });
    const setCookie = res.headers['set-cookie'];
    if (setCookie) cookieJar = setCookie.map(c => c.split(';')[0]).join('; ');
    console.log('✅ AimiliVPN 登录成功');
    return cookieJar;
  } catch (e) {
    console.error('❌ 登录失败:', e.response?.data || e.message);
    throw e;
  }
}

async function apiRequest(method, endpoint, data = null, retries = 3) {
  const url = `${AIMILIVPN_BASE}${endpoint}`;
  const headers = { Cookie: cookieJar };
  if (data) headers['Content-Type'] = 'application/json';
  let attempt = 0;
  while (attempt < retries) {
    try {
      const res = await axios({ method, url, data, headers, timeout: 30000 });
      return res.data;
    } catch (e) {
      const status = e.response?.status;
      if (status === 401) {
        console.warn('⚠️ 会话过期，重新登录...');
        await loginAimili();
        headers.Cookie = cookieJar;
        continue;
      }
      if (status === 409) {
        const wait = (attempt + 1) * 1000;
        console.warn(`⚠️ 409 锁冲突，等待 ${wait}ms 后重试 (${attempt+1}/${retries})`);
        await sleep(wait);
        attempt++;
        continue;
      }
      const errMsg = e.response?.data?.error || e.message;
      throw new Error(`API 请求失败 (${status}): ${errMsg}`);
    }
  }
  throw new Error(`API 请求重试 ${retries} 次后仍失败`);
}

async function getExitSlots()        { return apiRequest('get', '/api/exit_slots'); }
async function startSlot(slot)       { return apiRequest('post', '/api/start_slot', { slot }); }
async function assignNodeToSlot(slot, nodeId) { return apiRequest('post', '/api/assign_slot_node', { slot, node_id: nodeId }); }
async function getNodes()            { const res = await apiRequest('get', '/api/nodes'); return res.nodes || []; }

// ---------- 节点池管理器（随机分配） ----------
class NodePool {
  constructor(nodes) {
    this.nodes = nodes.filter(n => n.probe_status === 'available');
    this.used = new Set();
    this.lock = false;
    console.log(`📦 节点池初始化: 共 ${this.nodes.length} 个可用节点`);
  }

  async acquire() {
    while (this.lock) await sleep(50);
    this.lock = true;
    // 获取所有未使用节点
    const available = this.nodes.filter(n => !this.used.has(n.id));
    let node = null;
    if (available.length > 0) {
      // 随机选取一个
      const randomIndex = Math.floor(Math.random() * available.length);
      node = available[randomIndex];
      this.used.add(node.id);
    }
    this.lock = false;
    return node;
  }

  release(nodeId) {
    this.used.delete(nodeId);
  }

  get usedCount() { return this.used.size; }
  get totalCount() { return this.nodes.length; }
  get usedIds() { return Array.from(this.used); }
}

// ---------- 等待槽位上线 ----------
async function waitSlotUp(slot, timeout = 30000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const data = await getExitSlots();
    const info = data.slots.find(s => s.slot === slot);
    if (info && info.status === 'up') return true;
    await sleep(1000);
  }
  return false;
}

// ---------- 检测代理出口 IP ----------
async function checkProxyIP(proxyUrl) {
  const agent = new SocksProxyAgent(proxyUrl);
  const testUrls = [
    'https://ipinfo.io/ip',
    'https://api.ipify.org',
    'http://cip.cc'
  ];
  const shuffled = testUrls.sort(() => Math.random() - 0.5);
  for (const url of shuffled) {
    try {
      const response = await axios.get(url, {
        httpAgent: agent,
        httpsAgent: agent,
        timeout: 10000,
      });
      const ip = (response.data || '').trim();
      if (ip && /^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
        console.log(`   ✅ 检测到出口 IP: ${ip}`);
        return true;
      }
    } catch (e) {}
  }
  return false;
}

// ---------- 播放相关（原样保留） ----------
function getRandomFingerprint() {
  const viewports = [
    { width: 1280, height: 720 },
    { width: 1366, height: 768 },
    { width: 1440, height: 900 },
    { width: 1536, height: 864 },
    { width: 1920, height: 1080 }
  ];
  const platforms = [
    'Win32', 'Win64', 'MacIntel', 'MacPPC',
    'Linux x86_64', 'Linux i686', 'Linux armv8l', 'Linux armv7l',
    'iPhone', 'iPad', 'iPod', 'Android'
  ];
  const hardwareConcurrency = [4, 6, 8, 12, 16];
  const deviceMemory = [4, 8, 16];
  const localeList = [
    'zh-CN', 'zh-TW', 'en-US', 'en-GB', 'ja-JP', 'ko-KR',
    'fr-FR', 'de-DE', 'es-ES', 'pt-BR', 'ru-RU', 'it-IT',
    'ar-SA', 'hi-IN', 'th-TH', 'vi-VN', 'id-ID', 'tr-TR'
  ];
  const language = localeList[Math.floor(Math.random() * localeList.length)];
  let timezone = 'Asia/Shanghai';
  try {
    const tzList = timezones().map(t => t.name);
    if (tzList.length) timezone = tzList[Math.floor(Math.random() * tzList.length)];
  } catch {
    const fallback = ['Asia/Shanghai', 'Asia/Tokyo', 'America/New_York', 'Europe/London'];
    timezone = fallback[Math.floor(Math.random() * fallback.length)];
  }
  return {
    viewport: viewports[Math.floor(Math.random() * viewports.length)],
    platform: platforms[Math.floor(Math.random() * platforms.length)],
    hardwareConcurrency: hardwareConcurrency[Math.floor(Math.random() * hardwareConcurrency.length)],
    deviceMemory: deviceMemory[Math.floor(Math.random() * deviceMemory.length)],
    language,
    timezone
  };
}

function getRandomUserAgent() {
  let ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36';
  try {
    const randomUA = randomUseragent.getRandom();
    if (randomUA) ua = randomUA;
  } catch {
    const fallbackUAs = [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
    ];
    ua = fallbackUAs[Math.floor(Math.random() * fallbackUAs.length)];
  }
  return ua;
}

function buildProxyConfig(proxy) {
  if (!proxy) return undefined;
  const normalizedProxy = proxy.replace(/^socks5h:\/\//i, 'socks5://');
  try {
    const url = new URL(normalizedProxy);
    const protocol = url.protocol.toLowerCase() === 'socks5h:' ? 'socks5:' : url.protocol;
    const server = `${protocol}//${url.hostname}${url.port ? `:${url.port}` : ''}`;
    const config = { server };
    if (url.username) config.username = decodeURIComponent(url.username);
    if (url.password) config.password = decodeURIComponent(url.password);
    return config;
  } catch {
    return { server: normalizedProxy };
  }
}

async function safeGoto(page, url, logPrefix) {
  const attempts = [
    { waitUntil: 'commit', timeout: 30000 },
    { waitUntil: 'domcontentloaded', timeout: 45000 },
    { waitUntil: 'load', timeout: 45000 },
  ];
  for (const attempt of attempts) {
    try {
      await page.goto(url, attempt);
      return true;
    } catch (error) {
      console.log(`${logPrefix} 页面加载失败(${attempt.waitUntil})：${error.message}`);
    }
  }
  return false;
}

async function handleAdPopup(context, logPrefix) {
  try {
    const popup = await context.waitForEvent('page', { timeout: AD_POPUP_TIMEOUT });
    console.log(`${logPrefix} 📺 检测到广告弹窗，等待加载并播放...`);
    await popup.waitForLoadState('domcontentloaded', { timeout: 10000 }).catch(() => {});
    console.log(`${logPrefix} ⏳ 广告播放中，等待 ${AD_WAIT_SECONDS} 秒...`);
    await popup.waitForTimeout(AD_WAIT_SECONDS * 1000);
    console.log(`${logPrefix} 🚫 广告播放完毕，关闭广告页`);
    await popup.close();
    await sleep(2000);
    return true;
  } catch (error) {
    if (error.message && error.message.includes('Timeout')) {
      console.log(`${logPrefix} ℹ️ 未检测到广告弹窗（或超时），继续播放`);
    } else {
      console.log(`${logPrefix} ⚠️ 广告处理异常（忽略）：${error.message}`);
    }
    return false;
  }
}

async function playVideo(page, logPrefix) {
  async function findVideoFrame() {
    if (!page || page.isClosed()) return null;
    try {
      const frames = page.frames();
      const mainHasVideo = await page.evaluate(() => !!document.querySelector('video, audio'));
      if (mainHasVideo) return page.mainFrame();
      for (let i = 0; i < frames.length; i++) {
        const frame = frames[i];
        if (frame === page.mainFrame()) continue;
        const hasVideo = await frame.evaluate(() => !!document.querySelector('video, audio'));
        if (hasVideo) return frame;
      }
      return null;
    } catch (e) {
      console.log(`${logPrefix} 查找视频帧时出错：${e.message}`);
      return null;
    }
  }

  const playSelectors = [
    'button[aria-label*="play" i]', 'button[aria-label*="播放" i]',
    'button:has-text("Play")', 'button:has-text("播放")',
    '[role="button"][aria-label*="play" i]',
    '.vjs-big-play-button', '.jw-icon-playback', '.ytp-play-button',
    'button[data-testid="play-button"]', 'button[class*="play"]',
    'div[class*="play"]:not([class*="pause"])',
  ];

  let targetFrame = await findVideoFrame();

  if (!targetFrame) {
    console.log(`${logPrefix} 未找到视频，尝试点击播放按钮...`);
    let clicked = false;
    for (const selector of playSelectors) {
      try {
        if (!page || page.isClosed()) break;
        const el = await page.waitForSelector(selector, { timeout: 2000 });
        if (el) {
          await el.click({ timeout: 2000 });
          console.log(`${logPrefix} ✅ 点击成功: ${selector}`);
          clicked = true;
          break;
        }
      } catch {}
    }
    if (!clicked && page && !page.isClosed()) {
      try {
        await page.evaluate(() => {
          const media = document.querySelector('video, audio');
          if (media) { media.muted = true; media.play().catch(() => {}); }
        });
        console.log(`${logPrefix} ℹ️ 使用 JS 调用 play() 尝试播放`);
      } catch (e) {
        console.log(`${logPrefix} 执行 play() 失败：${e.message}`);
      }
    }
    const startTime = Date.now();
    while (Date.now() - startTime < 30000) {
      if (!page || page.isClosed()) break;
      await sleep(1000);
      targetFrame = await findVideoFrame();
      if (targetFrame) break;
    }
  }

  if (!targetFrame) {
    console.log(`${logPrefix} ❌ 未找到视频元素`);
    return { success: false, playedDuration: 0 };
  }

  console.log(`${logPrefix} 🎯 找到视频，执行播放...`);

  let frameClicked = false;
  for (const selector of playSelectors) {
    try {
      if (!targetFrame) break;
      const el = await targetFrame.waitForSelector(selector, { timeout: 2000 });
      if (el) {
        await el.click({ timeout: 2000 });
        frameClicked = true;
        break;
      }
    } catch (e) {}
  }

  if (!frameClicked && targetFrame) {
    try {
      await targetFrame.evaluate(() => {
        const media = document.querySelector('video, audio');
        if (media) { media.muted = true; media.play().catch(() => {}); }
      });
    } catch (e) {
      console.log(`${logPrefix} 在 frame 中执行 play() 失败：${e.message}`);
    }
  }

  let playStart = { success: false, startTime: 0 };
  if (targetFrame) {
    try {
      playStart = await targetFrame.waitForFunction(
        () => {
          const video = document.querySelector('video, audio');
          if (video && video.currentTime > 0 && !video.paused) {
            return video.currentTime;
          }
          return false;
        },
        { timeout: 30000, polling: 500 }
      ).then(ct => ({ success: true, startTime: ct }))
       .catch(() => ({ success: false, startTime: 0 }));
    } catch (e) {
      console.log(`${logPrefix} 等待播放开始出错：${e.message}`);
    }
  }

  let playedDuration = 0;
  if (playStart.success && targetFrame) {
    try {
      await sleep(PLAY_WAIT_SECONDS * 1000);
      const endTime = await targetFrame.evaluate(() => {
        const video = document.querySelector('video, audio');
        return video ? video.currentTime : 0;
      });
      playedDuration = endTime - playStart.startTime;
      if (playedDuration < 0) playedDuration = 0;
    } catch (e) {
      console.log(`${logPrefix} 记录播放时长出错：${e.message}`);
    }
  }

  console.log(`${logPrefix} ${playStart.success ? '🎵 播放成功！' : '❌ 未检测到播放'} 播放了 ${playedDuration.toFixed(1)} 秒`);
  return { success: playStart.success, playedDuration };
}

async function runSingleProxy(browser, proxyUrl, label) {
  const logPrefix = `[${label}]`;
  const userAgent = getRandomUserAgent();
  const fp = getRandomFingerprint();

  console.log(`🚀 ${logPrefix} | UA: ${userAgent.substring(0,70)}... | 分辨率: ${fp.viewport.width}x${fp.viewport.height}`);

  let context = null, page = null;
  try {
    context = await browser.newContext({
      viewport: fp.viewport,
      userAgent: userAgent,
      locale: fp.language,
      timezoneId: fp.timezone,
      bypassCSP: true,
      ignoreHTTPSErrors: true,
      proxy: buildProxyConfig(proxyUrl),
    });

    await context.addInitScript((fp) => {
      Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
      Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
      Object.defineProperty(navigator, 'languages', { get: () => [fp.language, 'zh'] });
      Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => fp.hardwareConcurrency });
      Object.defineProperty(navigator, 'deviceMemory', { get: () => fp.deviceMemory });
      Object.defineProperty(navigator, 'platform', { get: () => fp.platform });

      const originalGetContext = HTMLCanvasElement.prototype.getContext;
      HTMLCanvasElement.prototype.getContext = function(type) {
        const context = originalGetContext.apply(this, arguments);
        if (type === '2d') {
          const originalFillText = context.fillText;
          context.fillText = function(text, x, y) {
            arguments[0] = text + Math.random().toString(36).substring(2, 5);
            return originalFillText.apply(this, arguments);
          };
        }
        return context;
      };

      const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
      WebGLRenderingContext.prototype.getParameter = function(parameter) {
        if (parameter === 37445) return "Intel Inc.";
        if (parameter === 37446) return "Intel Iris OpenGL Engine";
        return originalGetParameter.apply(this, arguments);
      };
    }, fp);

    page = await context.newPage();
    page.setDefaultTimeout(15000);
    page.setDefaultNavigationTimeout(60000);

    console.log(`🚀 ${logPrefix} 开始加载页面...`);
    const ok = await safeGoto(page, TARGET_URL, logPrefix);
    if (!ok) {
      console.log(`${logPrefix} ❌ 页面加载最终失败`);
      return { label, proxy: proxyUrl, success: false, playedDuration: 0, error: 'page load failed' };
    }

    await sleep(2000);

    const playSelectors = [
      'button[aria-label*="play" i]', 'button[aria-label*="播放" i]',
      'button:has-text("Play")', 'button:has-text("播放")',
      '[role="button"][aria-label*="play" i]',
      '.vjs-big-play-button', '.jw-icon-playback', '.ytp-play-button',
      'button[data-testid="play-button"]', 'button[class*="play"]',
      'div[class*="play"]:not([class*="pause"])',
    ];

    let clicked = false;
    for (const selector of playSelectors) {
      try {
        const el = await page.waitForSelector(selector, { timeout: 2000 });
        if (el) {
          const adPromise = handleAdPopup(context, logPrefix);
          await el.click({ timeout: 2000 });
          console.log(`${logPrefix} ✅ 点击成功: ${selector}`);
          clicked = true;
          await adPromise;
          break;
        }
      } catch {}
    }

    if (!clicked) {
      console.log(`${logPrefix} ℹ️ 未点击播放按钮，尝试 JS play`);
      try {
        await page.evaluate(() => {
          const media = document.querySelector('video, audio');
          if (media) { media.muted = true; media.play().catch(() => {}); }
        });
      } catch (e) {
        console.log(`${logPrefix} JS play 失败：${e.message}`);
      }
    }

    const playResult = await playVideo(page, logPrefix);
    return { label, proxy: proxyUrl, success: playResult.success, playedDuration: playResult.playedDuration, timestamp: new Date().toISOString() };

  } catch (error) {
    console.error(`${logPrefix} ❌ 执行异常: ${error.message}`);
    return { label, proxy: proxyUrl, success: false, playedDuration: 0, error: error.message };
  } finally {
    if (page && !page.isClosed()) await page.close().catch(() => {});
    if (context) await context.close().catch(() => {});
  }
}

// ================== 并发控制（信号量） ==================
function createSemaphore(max) {
  let running = 0, queue = [];
  const next = () => { if (queue.length > 0 && running < max) { running++; queue.shift()(); } };
  return {
    acquire: () => new Promise(resolve => {
      if (running < max) { running++; resolve(); }
      else queue.push(resolve);
    }),
    release: () => { running--; next(); }
  };
}

// ================== 主流程 ==================
(async () => {
  await loginAimili();

  try {
    const slotsData = await getExitSlots();
    if (slotsData.config && slotsData.config.count > 0) {
      const firstSlot = slotsData.slots.find(s => s.port);
      if (firstSlot) {
        proxyPortBase = firstSlot.port - firstSlot.slot;
        console.log(`📡 从 API 获取到端口基址: ${proxyPortBase}`);
      }
    }
  } catch (e) {
    console.warn('⚠️ 无法获取槽位配置，使用默认端口基址 17928');
  }

  const browser = await chromium.launch({
    headless: !process.env.PWDEBUG,
    args: ['--no-sandbox', '--autoplay-policy=no-user-gesture-required']
  });

  const sem = createSemaphore(MAX_CONCURRENT);
  let lockChain = Promise.resolve();   // 全局共享锁

  let round = 0;
  const allResults = [];

  const processSlot = async (slot, roundNum, nodePool) => {
    console.log(`\n🔄 第 ${roundNum} 轮，槽位 ${slot} 开始处理...`);

    for (let retry = 1; retry <= MAX_IP_RETRY; retry++) {
      console.log(`   ⏳ 尝试 ${retry}/${MAX_IP_RETRY} 分配节点并检测出口 IP...`);

      const node = await nodePool.acquire();
      if (!node) {
        console.error(`❌ 节点池已空，无法继续`);
        return { slot, success: false, error: 'no available nodes' };
      }
      console.log(`   📌 分配节点: ${node.id} (${node.ip || node.remote_host})`);

      try {
        const data = await getExitSlots();
        const info = data.slots.find(s => s.slot === slot);
        if (!info) {
          console.error(`❌ 槽位 ${slot} 不存在`);
          nodePool.release(node.id);
          return { slot, success: false, error: 'slot not found' };
        }
        if (info.status === 'paused') {
          console.log(`⏳ 槽位 ${slot} 暂停，尝试启动...`);
          await startSlot(slot);
          if (!await waitSlotUp(slot)) {
            console.error(`❌ 启动超时`);
            nodePool.release(node.id);
            return { slot, success: false, error: 'start timeout' };
          }
          console.log(`✅ 槽位 ${slot} 已启动`);
        }
        if (info.port) proxyPortBase = info.port - slot;
      } catch (e) {
        console.error(`❌ 状态检查失败: ${e.message}`);
        nodePool.release(node.id);
        return { slot, success: false, error: e.message };
      }

      // ---------- 分配节点（严格串行） ----------
      let assignOk = false;
      await lockChain;
      let releaseLock;
      lockChain = new Promise(resolve => { releaseLock = resolve; });
      try {
        console.log(`   🔒 已获取分配锁，开始执行 assignNodeToSlot`);
        const assignResult = await assignNodeToSlot(slot, node.id);
        if (assignResult.ok) {
          console.log(`   ✅ 节点 ${node.id} 分配成功`);
          assignOk = true;
        } else {
          console.log(`   ❌ 分配失败: ${assignResult.error || '未知错误'}`);
          nodePool.release(node.id);
        }
      } catch (e) {
        console.error(`   ❌ 分配异常: ${e.message}`);
        nodePool.release(node.id);
      } finally {
        releaseLock();
        console.log(`   🔓 分配锁已释放`);
      }

      if (!assignOk) continue;

      if (!await waitSlotUp(slot)) {
        console.error(`❌ 槽位 ${slot} 启动超时`);
        nodePool.release(node.id);
        continue;
      }

      let port = proxyPortBase + slot;
      try {
        const data = await getExitSlots();
        const info = data.slots.find(s => s.slot === slot);
        if (info && info.port) port = info.port;
      } catch (e) {}

      const proxyUrl = `socks5://${AIMILIVPN_PROXY_HOST}:${port}`;
      console.log(`✅ 槽位 ${slot} 已就绪，代理: ${proxyUrl}`);

      console.log(`🔍 检测出口 IP...`);
      const ipOk = await checkProxyIP(proxyUrl);
      if (ipOk) {
        const result = await runSingleProxy(browser, proxyUrl, `slot-${slot}`);
        console.log(`📊 槽位 ${slot} 播放结果: ${result.success ? '成功' : '失败'}，播放 ${result.playedDuration.toFixed(1)} 秒`);
        return { slot, nodeId: node.id, ...result };
      } else {
        console.log(`   ❌ 出口 IP 检测失败，释放节点 ${node.id} 并重试 (${retry}/${MAX_IP_RETRY})`);
        nodePool.release(node.id);
        await sleep(2000);
      }
    }

    console.log(`❌ 槽位 ${slot} 经过 ${MAX_IP_RETRY} 次尝试仍无法获得有效出口 IP，放弃本轮`);
    return { slot, success: false, error: 'IP check failed after retries' };
  };

  // ---------- 无限循环 ----------
  while (true) {
    round++;
    let activeSlots = [];
    let nodePool = null;

    try {
      const slotsData = await getExitSlots();
      activeSlots = slotsData.config.active || [];
      if (activeSlots.length === 0) {
        console.log('⚠️ 没有激活的槽位，等待重试...');
        await sleep(60000);
        continue;
      }

      const nodes = await getNodes();
      const availableNodes = nodes.filter(n => n.probe_status === 'available');
      if (availableNodes.length === 0) {
        console.log('⚠️ 没有可用的节点，等待重试...');
        await sleep(60000);
        continue;
      }
      nodePool = new NodePool(availableNodes);
      console.log(`📋 可用槽位: ${activeSlots.join(', ')}`);
      console.log(`📊 可用节点数: ${nodePool.totalCount}`);
    } catch (e) {
      console.error('❌ 获取槽位/节点列表失败，等待重试...', e.message);
      await sleep(10000);
      continue;
    }

    console.log(`\n🚀 开始第 ${round} 轮，共 ${activeSlots.length} 个槽位，节点池 ${nodePool.totalCount} 个，最大并发 ${MAX_CONCURRENT}`);

    const tasks = activeSlots.map(slot =>
      sem.acquire().then(() => processSlot(slot, round, nodePool).finally(() => sem.release()))
    );

    const roundResults = await Promise.all(tasks);
    allResults.push({ round, results: roundResults });
    fs.writeFileSync('play_results.json', JSON.stringify(allResults, null, 2));

    const successCount = roundResults.filter(r => r.success).length;
    console.log(`\n🎉 第 ${round} 轮完成，成功: ${successCount}/${activeSlots.length}`);
    console.log(`📌 本轮使用的节点 ID: ${nodePool.usedIds.join(', ') || '无'}`);
    console.log(`📊 剩余可用节点: ${nodePool.totalCount - nodePool.usedCount}`);

    console.log(`⏳ 等待 ${LOOP_INTERVAL_SECONDS} 秒后开始下一轮...`);
    await sleep(LOOP_INTERVAL_SECONDS * 1000);
  }
})();
