import {test,expect} from '@playwright/test';
import {readFile,mkdir} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const shots=path.join(root,'artifacts/web-workbench/screenshots');
const stamp=Date.now();
test.beforeAll(async()=>{await mkdir(shots,{recursive:true});});
test.beforeEach(async({page})=>{
 const errors=[];page.on('pageerror',error=>errors.push(error.message));test.info().errorsFromBrowser=errors;
 await page.goto('/');await expect(page.locator('[data-testid="view-overview"] h1')).toBeVisible();
});
test.afterEach(async()=>{expect(test.info().errorsFromBrowser).toEqual([]);});
async function go(page,route){await page.locator(`[data-route="${route}"]`).click();await expect(page.locator(`[data-testid="view-${route}"] h1`)).toBeVisible();}
async function newCase(page,label){
 await go(page,'tasks');await page.getByText('创建独立案例',{exact:true}).click();await page.getByLabel('新案例名称').fill(label);await page.getByRole('button',{name:'创建并切换',exact:true}).click();
 await expect(page.getByLabel('当前案例').locator('option:checked')).toHaveText(label);await expect(page.locator('[data-testid="view-tasks"] h1')).toBeVisible();
}
async function runPreset(page,preset){
 await page.getByLabel('实验预设').selectOption(preset);await page.getByTestId('submit-experiment').click();
 await expect(page.locator('.job-row.selected')).toBeVisible();await expect(page.locator('.job-row.selected')).toContainText('已完成',{timeout:60000});
}

test('real vmde evidence: all research views, events and snapshots',async({page})=>{
 await expect(page.locator('main')).toContainText('904');
 await page.screenshot({path:path.join(shots,'overview-desktop.png'),fullPage:true});
 await go(page,'code');await expect(page.locator('main svg').first()).toBeVisible();await expect(page.locator('main')).toContainText('498a50');
 await page.screenshot({path:path.join(shots,'code-desktop.png'),fullPage:true});
 await go(page,'timeline');await expect(page.locator('main')).toContainText('PID');await expect(page.locator('.timeline-event,.event-row').first()).toBeVisible();
 await page.getByLabel('事件类型',{exact:true}).selectOption('breakpoint');await page.locator('.event-row').first().click();await expect(page.locator('.event-details')).toContainText('寄存器');
 await page.locator('.snapshot-row button').first().click();await expect(page.getByRole('dialog')).toContainText('SHA-256');await expect(page.locator('.evidence-text')).toBeVisible();await page.getByLabel('关闭证据').click();
 await page.getByLabel('选择运行',{exact:true}).selectOption('startup-original-qsettings');await page.getByLabel('事件类型',{exact:true}).selectOption('');await expect(page.locator('.run-meta')).toContainText('20312');await expect(page.locator('.run-meta')).toContainText('失败');
 await page.screenshot({path:path.join(shots,'timeline-desktop.png'),fullPage:true});
 await go(page,'validation');await expect(page.locator('main')).toContainText('904');await expect(page.locator('main tbody tr').first()).toBeVisible();
 await page.locator('main tbody tr').first().getByRole('button').click();await expect(page.locator('main')).toContainText('原始比较报告未保留候选输出');
 await page.getByLabel('比较结果筛选',{exact:true}).selectOption('mismatched');await expect(page.locator('main')).toContainText('没有匹配的比较记录');await page.getByLabel('比较结果筛选',{exact:true}).selectOption('matched');await expect(page.locator('main tbody tr')).toHaveCount(25);await page.getByRole('button',{name:'下一页',exact:true}).click();await expect(page.locator('.pagination')).toContainText('26–50');
 await page.screenshot({path:path.join(shots,'validation-desktop.png'),fullPage:true});
});

test('switching models discards an earlier failed evaluation',async({page})=>{
 await go(page,'lab');await page.getByLabel('选择实验模型').selectOption('mba_u8');
 let release;const delayed=new Promise(resolve=>{release=resolve;});let entered;const requested=new Promise(resolve=>{entered=resolve;});
 await page.route('**/api/cases/workbench/models/mba_u8/evaluate',async route=>{entered();await delayed;await route.fulfill({status:400,contentType:'application/json',body:JSON.stringify({error:{code:'INVALID_OLD_MODEL',message:'旧模型故障不应覆盖新模型'}})});});
 await page.getByTestId('evaluate-model').click();await requested;await page.getByLabel('选择实验模型').selectOption('add_u8');
 const response=page.waitForResponse(r=>r.url().endsWith('/models/mba_u8/evaluate'));release();await response;
 // Drain the delayed response and its UI error handler before observing the new model.
 await page.waitForTimeout(100);
 await expect(page.getByLabel('选择实验模型')).toHaveValue('add_u8');await expect(page.locator('main')).not.toContainText('INVALID_OLD_MODEL');
 await page.getByLabel('输入 a',{exact:true}).fill('1');await page.getByLabel('输入 b',{exact:true}).fill('2');await page.getByTestId('evaluate-model').click();await expect(page.locator('.output-values')).toContainText('0x03');
});

test('model laboratory uses actual typed evaluation and parameter previews',async({page})=>{
 await go(page,'lab');await page.getByLabel('选择实验模型').selectOption('add_u8');await page.getByLabel('输入 a',{exact:true}).fill('250');await page.getByLabel('输入 b',{exact:true}).fill('10');await page.getByTestId('evaluate-model').click();
 await expect(page.locator('.output-values')).toContainText('0x04');await expect(page.locator('.lab-results')).toContainText('bv_add');
 await page.getByLabel('选择实验模型').selectOption('affine_initial');await page.getByLabel('输入 x',{exact:true}).fill('2');await page.getByLabel('参数 a',{exact:true}).fill('2');await page.getByLabel('参数 b',{exact:true}).fill('1');await page.getByTestId('evaluate-model').click();
 await expect(page.locator('.output-values')).toContainText('5');await expect(page.locator('.lab-results')).toContainText('参数预览');await expect(page.locator('svg.curve-chart')).toBeVisible();
 await page.screenshot({path:path.join(shots,'lab-desktop.png'),fullPage:true});
});

test('real UI creates case, fits Handwired, simplifies, exports, inspects and cancels',async({page})=>{
 await newCase(page,`浏览器验收 ${stamp}`);await runPreset(page,'fit-handwired');
 await expect(page.locator('.job-detail-title')).toContainText('fit_numeric');await expect(page.locator('.job-detail-title')).toContainText('已完成');
 await page.getByTestId('export-job').click();await expect(page.locator('.download-files')).toContainText('manifest.json',{timeout:60000});
 const report=page.locator('.download-files a').filter({hasText:'report.md'}).first();const href=await report.getAttribute('href');const response=await page.request.get(href);expect(response.ok()).toBeTruthy();expect(await response.text()).toContain('Wirefit report');
 await runPreset(page,'simplify-mba');await expect(page.locator('.task-monitor')).toContainText('proved');
 await page.screenshot({path:path.join(shots,'tasks-desktop.png'),fullPage:true});
 const caseId=await page.getByLabel('当前案例').inputValue();const saved=(await (await page.request.get(`/api/cases/${caseId}`)).json()).data;const fit=saved.runs.find(run=>run.result?.fit?.candidate_model_id)?.result.fit;expect(fit).toBeTruthy();
 await go(page,'lab');await expect(page.locator('main')).toContainText(fit.status==='failed'?'拟合未通过':'三分割策略匹配');await expect(page.locator('.loss-chart svg').first()).toBeVisible();await page.screenshot({path:path.join(shots,'lab-fit-desktop.png'),fullPage:true});
 await go(page,'tasks');await page.getByText('本机文件分析',{exact:true}).click();await page.getByLabel('本机分析类型').selectOption('inspect');await page.getByLabel('分析配置').selectOption('pe-static');await page.getByLabel('目标文件绝对路径').fill('E:\\Vector Magic 2021\\vmde.exe');await page.getByTestId('submit-native').click();await expect(page.locator('.job-row.selected')).toContainText('已完成',{timeout:30000});await expect(page.locator('.task-monitor')).toContainText('inspect_binary');
 await newCase(page,`取消验收 ${stamp}`);await page.getByLabel('实验预设').selectOption('fit-handwired');await page.getByTestId('submit-experiment').click();const cancel=page.getByTestId('cancel-job');await expect(cancel).toBeEnabled();await cancel.click();await expect(page.locator('.job-row.selected')).toContainText('已取消',{timeout:30000});
});

test('model import is inert, malformed input is visible, and mobile is usable',async({page})=>{
 await newCase(page,`导入验收 ${stamp}`);const model=JSON.parse(await readFile(path.join(root,'examples/model.add-u8.json'),'utf8'));model.model_id=`web_import_${stamp}`;model.title='<img src=x onerror="window.__wirefit_injected=true">';
 await page.getByText('导入显式模型',{exact:true}).click();await page.getByLabel('导入模型 JSON').fill(JSON.stringify(model));await page.getByRole('button',{name:'导入模型',exact:true}).click();await expect(page.locator('main')).toContainText('模型已通过服务校验并导入');
 await go(page,'lab');await page.getByLabel('选择实验模型').selectOption(model.model_id);expect(await page.locator('img[src="x"]').count()).toBe(0);expect(await page.evaluate(()=>window.__wirefit_injected)).toBeUndefined();
 const negative=JSON.parse(await readFile(path.join(root,'examples/model.affine-initial.json'),'utf8'));negative.model_id=`web_negative_zero_${stamp}`;negative.definition.parameters.b.bits='0x80000000';
 await go(page,'tasks');await page.getByText('导入显式模型',{exact:true}).click();await page.getByLabel('导入模型 JSON').fill(JSON.stringify(negative));await page.getByRole('button',{name:'导入模型',exact:true}).click();await expect(page.locator('main')).toContainText('模型已通过服务校验并导入');
 await go(page,'lab');await page.getByLabel('选择实验模型').selectOption(negative.model_id);await expect(page.getByLabel('参数 b',{exact:true})).toHaveValue('-0');await page.getByLabel('输入 x',{exact:true}).fill('-0');await page.getByTestId('evaluate-model').click();await expect(page.locator('.output-values')).toContainText('-0 · 0x80000000');await expect(page.locator('.lab-results')).not.toContainText('参数预览');
 await go(page,'tasks');await page.getByTestId('experiment-json').fill('{');await page.getByTestId('submit-experiment').click();await expect(page.locator('main')).toContainText('实验请求不是有效的 JSON');
 await page.setViewportSize({width:390,height:844});await go(page,'overview');await expect(page.locator('main h1')).toBeVisible();await page.screenshot({path:path.join(shots,'overview-mobile.png'),fullPage:true});
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+2)).toBeTruthy();
});
