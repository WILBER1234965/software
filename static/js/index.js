document.addEventListener('DOMContentLoaded', function() {
    // Animación suave de las tarjetas de productos al aparecer
    const productCards = document.querySelectorAll('.product-card');
    const observer = new IntersectionObserver(entries => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = 1;
                entry.target.style.transform = "translateY(0)";
            } else {
                entry.target.style.opacity = 0;
                entry.target.style.transform = "translateY(20px)";
            }
        });
    }, {
        threshold: 0.1
    });

    productCards.forEach(card => {
        card.style.opacity = 0;
        card.style.transform = "translateY(20px)";
        observer.observe(card);
    });

    // Interactividad del botón de búsqueda
    const searchButton = document.querySelector('.btn-primary');
    searchButton.addEventListener('mouseover', function() {
        this.style.transform = 'scale(1.05)';
    });
    searchButton.addEventListener('mouseout', function() {
        this.style.transform = 'scale(1)';
    });
});
