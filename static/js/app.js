// CSRFトークンをaxiosに設定
document.addEventListener('DOMContentLoaded', function () {
    const csrfToken = document.querySelector('input[name="_csrf_token"]');
    if (csrfToken) {
        axios.defaults.headers.common['X-CSRF-Token'] = csrfToken.value;
    }

    // ダークモード切り替え
    const toggleThemeButton = document.getElementById('toggle-theme');
    if (toggleThemeButton) {
        toggleThemeButton.addEventListener('click', function () {
            document.body.classList.toggle('dark-mode');
            const theme = document.body.classList.contains('dark-mode') ? 'dark' : 'light';
            axios.post('/set_theme', { theme: theme })
                .catch(err => console.error('テーマの保存に失敗しました:', err));
        });
    }
});