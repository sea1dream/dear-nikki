---
title: itextbook下载PDF
published: 2026-08-19
description: 
tags: js
category: 生活小技巧
draft: false

---

### 控制台执行JS

在阅读器页面 F12 → Console 粘贴执行：

```js
(async function() {
  // 兼容不同PDF.js集成方式，优先取标准全局对象
  const pdfApp = window.PDFViewerApplication || window.PDFView || window.pdfViewerApplication;
  if (!pdfApp || !pdfApp.pdfDocument) {
    console.error('未找到PDF文档实例，请确保页面已加载出第一页内容');
    return;
  }

  // 清理文件名非法字符（兼容Windows/macOS/Linux）
  const sanitizeFileName = (name) => {
    return name
      .replace(/[\\/:*?"<>|\r\n\t]/g, '_')  // 替换系统不允许的字符
      .replace(/\s+/g, ' ')                 // 合并多余空格
      .trim();
  };

  let fileName = '完整电子书';
  try {
    console.log('正在读取PDF元数据，提取书名...');
    // 从PDF内置文档信息中提取标题（最准确的真实书名）
    const metadata = await pdfApp.pdfDocument.getMetadata();
    const pdfTitle = metadata?.info?.Title;
    
    if (pdfTitle && pdfTitle.trim()) {
      fileName = pdfTitle.trim();
    } else {
      // PDF无内置标题时，降级使用网页标题
      fileName = document.title || fileName;
    }
  } catch (err) {
    console.warn('读取书名失败，将使用默认文件名', err);
  }

  // 拼接最终文件名
  const saveName = sanitizeFileName(fileName) + '.pdf';
  console.log(`正在导出：${saveName}，请勿关闭页面...`);

  // 获取完整PDF二进制数据并下载
  const data = await pdfApp.pdfDocument.getData();
  const blob = new Blob([data], { type: 'application/pdf' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = saveName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  console.log('导出完成');
})();
```
