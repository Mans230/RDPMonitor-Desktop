(() => {
  const button = document.getElementById('copy-checksum');
  const checksum = document.getElementById('release-checksum');
  const status = document.getElementById('copy-status');
  if (!button || !checksum || !status) return;

  button.disabled = false;
  button.addEventListener('click', async () => {
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(checksum.textContent.trim());
      status.textContent = 'Checksum copied.';
    } catch {
      const selection = window.getSelection();
      if (selection) {
        const range = document.createRange();
        range.selectNodeContents(checksum);
        selection.removeAllRanges();
        selection.addRange(range);
        status.textContent = 'Automatic copying is unavailable. The checksum is selected for manual copying.';
      } else {
        status.textContent = 'Automatic copying is unavailable. Copy the checksum above or download its checksum file.';
      }
    }
  });
})();
