// Turns a .otp-boxes container of single-digit <input> boxes into a drop-in
// replacement for a plain text input: defines .value (get/set) and .focus()
// on the container itself, so view.js's existing otp-input.value/.focus()
// calls keep working unchanged, and a bubbled keydown still reaches it.
(() => {
  function wire(container) {
    const boxes = [...container.querySelectorAll('.otp-box')];
    if (!boxes.length) return;

    function currentValue() {
      return boxes.map(b => b.value).join('');
    }

    function setValue(str) {
      const digits = (str || '').replace(/\D/g, '').slice(0, boxes.length).split('');
      boxes.forEach((b, i) => {
        b.value = digits[i] || '';
        b.classList.toggle('otp-box-filled', !!digits[i]);
      });
    }

    Object.defineProperty(container, 'value', {
      get: currentValue,
      set: setValue,
      configurable: true,
    });
    container.focus = () => boxes[0].focus();

    boxes.forEach((box, i) => {
      box.addEventListener('input', () => {
        const digits = box.value.replace(/\D/g, '');
        if (digits.length > 1) {
          // Autofill (or a fast typer) dropped multiple digits into one box.
          setValue(currentValue().slice(0, i) + digits);
          boxes[Math.min(i + digits.length, boxes.length - 1)].focus();
          return;
        }
        box.value = digits;
        box.classList.toggle('otp-box-filled', !!digits);
        if (digits && i < boxes.length - 1) boxes[i + 1].focus();
      });

      box.addEventListener('keydown', (e) => {
        if (e.key === 'Backspace' && !box.value && i > 0) {
          boxes[i - 1].value = '';
          boxes[i - 1].classList.remove('otp-box-filled');
          boxes[i - 1].focus();
        } else if (e.key === 'ArrowLeft' && i > 0) {
          boxes[i - 1].focus();
        } else if (e.key === 'ArrowRight' && i < boxes.length - 1) {
          boxes[i + 1].focus();
        }
      });

      box.addEventListener('paste', (e) => {
        const text = (e.clipboardData || window.clipboardData)?.getData('text');
        if (!text) return;
        e.preventDefault();
        setValue(text);
        boxes[Math.min(currentValue().length, boxes.length - 1)].focus();
      });

      box.addEventListener('focus', () => box.select());
    });
  }

  document.querySelectorAll('.otp-boxes').forEach(wire);
})();
