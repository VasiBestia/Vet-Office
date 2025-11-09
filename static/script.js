function handleFormSubmit(formId) {
    const form = document.getElementById(formId);
    
    // Funcție pentru curățarea câmpurilor formularului (folosită pentru Register)
    function clearFormFields(currentForm) {
        currentForm.reset(); 
    }

    form.addEventListener('submit', function(e) {
        e.preventDefault(); 
        
        const formData = new FormData(form);

        // NOU: Afișează o notificare de procesare
        alert("Procesare în curs..."); 

        fetch(form.action, {
            method: form.method,
            body: formData
        })
        .then(response => {
            // Răspunsul este întotdeauna text
            return response.text(); 
        })
        .then(responseText => {
            // NOU: Mesajul este afișat direct din răspuns
            alert(responseText); 

            // Verificare pentru SUCCES (dacă începe cu SUCCES și nu este un login)
            if (responseText.startsWith("SUCCES")) {
                // Dacă este succes (pentru Register), resetează câmpurile
                if (formId === 'registerForm') {
                    clearFormFields(form);
                }
                // Daca este login, se poate face redirect aici la dashboard (opțional)
            }
            // Dacă este EROARE, pur și simplu afișează mesajul de eroare (care este deja un alert)
        })
        .catch(error => {
            alert("A apărut o eroare de comunicare cu serverul.");
            console.error('Eroare Fetch:', error);
        });
    });
}

// Inițializează funcția pentru ambele formulare
document.addEventListener('DOMContentLoaded', function() {
    // Asigură-te că ai adăugat id="registerForm" și id="loginForm" la tagurile <form> din HTML
    handleFormSubmit('registerForm');
    handleFormSubmit('loginForm');
});