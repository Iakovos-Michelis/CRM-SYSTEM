document.addEventListener('DOMContentLoaded', function() {
    const allForms = document.querySelectorAll('form');
    
    allForms.forEach(currentForm => {
        currentForm.addEventListener('submit', function(e) {
            const requiredFields = currentForm.querySelectorAll('input[required], select[required], textarea[required]');
            let formIsValid = true;
            
            requiredFields.forEach(field => {
                if (field.value.trim() === '') {
                    field.style.borderColor = '#d9534f';
                    field.style.backgroundColor = '#f8f8f8';
                    formIsValid = false;
                } else {
                    field.style.borderColor = '';
                    field.style.backgroundColor = '';
                }
            });
            
            if (!formIsValid) {
                e.preventDefault();
                alert('All fields must be completed before submission');
            }
        });
    });
});