document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('accessToken');
    if (!token) {
        alert('Você precisa estar logado para agendar uma quadra.');
        window.location.href = '/login.html';
        return;
    }

    // Elementos do DOM atualizados
    const quadrasContainer = document.getElementById('quadras-list-container');
    const dataInput = document.getElementById('data-input');
    const verHorariosBtn = document.getElementById('ver-horarios-btn');
    const horariosContainer = document.getElementById('horarios-container');
    const horariosSection = document.getElementById('horarios-disponiveis');
    const reservaFormSection = document.getElementById('formulario-reserva');
    const reservaForm = document.getElementById('reserva-form');

    let dataSelecionada = null;
    let horarioSelecionado = null;

    // --- 1. FUNÇÃO carregarQuadras (TOTALMENTE REESCRITA) ---
    // Agora cria os cartões visuais das quadras
    async function carregarQuadras() {
        try {
            const response = await fetch('/api/quadras');
            const data = await response.json();
            
            quadrasContainer.innerHTML = ''; // Limpa o container
            data.quadras.forEach(quadra => {
                // Cria o HTML para cada cartão de quadra
                const courtItemHTML = `
                    <label class="court-item" for="quadra-${quadra.id}">
                        <input type="radio" name="quadra-radio" id="quadra-${quadra.id}" value="${quadra.id}" class="court-radio">
                        <img src="${quadra.imagem_url}" alt="${quadra.nome}">
                        <div class="court-item-info">
                            <h3 class="court-name">${quadra.nome}</h3>
                            <p>${quadra.tipo}</p>
                        </div>
                    </label>
                `;
                quadrasContainer.innerHTML += courtItemHTML;
            });
            
            // Adiciona o evento de clique para o feedback visual (classe 'selected')
            document.querySelectorAll('.court-item').forEach(item => {
                item.addEventListener('click', () => {
                    document.querySelectorAll('.court-item').forEach(i => i.classList.remove('selected'));
                    item.classList.add('selected');
                });
            });

            // Seleciona a quadra vinda da URL (ex: ?quadra=2), se houver
            const urlParams = new URLSearchParams(window.location.search);
            const quadraIdFromUrl = urlParams.get('quadra');
            if (quadraIdFromUrl) {
                const radioToSelect = document.getElementById(`quadra-${quadraIdFromUrl}`);
                if (radioToSelect) {
                    radioToSelect.checked = true;
                    radioToSelect.closest('.court-item').classList.add('selected');
                }
            }

        } catch (error) {
            console.error('Erro ao carregar quadras:', error);
            quadrasContainer.innerHTML = '<p>Não foi possível carregar as quadras.</p>';
        }
    }
    
    // --- 2. FUNÇÃO buscarHorarios (MODIFICADA) ---
    // Agora busca o ID da quadra no rádio selecionado
    async function buscarHorarios() {
        const quadraSelecionadaRadio = document.querySelector('input[name="quadra-radio"]:checked');
        dataSelecionada = dataInput.value;

        if (!quadraSelecionadaRadio || !dataSelecionada) {
            alert('Por favor, selecione uma quadra e uma data.');
            return;
        }
        
        const quadraIdSelecionada = quadraSelecionadaRadio.value;

        try {
            const response = await fetch(`/api/horarios/${quadraIdSelecionada}/${dataSelecionada}`);
            const data = await response.json();
            
            horariosContainer.innerHTML = '';
            if (data.horarios.length === 0) {
                horariosContainer.innerHTML = '<p>Nenhum horário disponível para esta data.</p>';
            } else {
                data.horarios.forEach(horario => {
                    const btn = document.createElement('button');
                    btn.textContent = horario;
                    btn.classList.add('horario-btn');
                    btn.onclick = () => selecionarHorario(horario);
                    horariosContainer.appendChild(btn);
                });
            }
            horariosSection.classList.remove('hidden');
            reservaFormSection.classList.add('hidden');
        } catch (error) {
            console.error('Erro ao buscar horários:', error);
        }
    }

    // --- 3. FUNÇÃO selecionarHorario (MODIFICADA) ---
    // Agora busca o nome da quadra no cartão selecionado
    function selecionarHorario(horario) {
        horarioSelecionado = horario;
        const quadraSelecionadaCard = document.querySelector('.court-item.selected');
        const nomeDaQuadra = quadraSelecionadaCard.querySelector('.court-name').textContent;

        document.getElementById('quadra-selecionada-nome').textContent = nomeDaQuadra;
        document.getElementById('data-selecionada').textContent = new Date(dataSelecionada + 'T00:00:00').toLocaleDateString('pt-BR');
        document.getElementById('horario-selecionado').textContent = horario;

        reservaFormSection.classList.remove('hidden');
        window.scrollTo(0, document.body.scrollHeight);
    }
    
    // --- FUNÇÃO submeterReserva (MODIFICADA) ---
    // Garante que o ID da quadra seja pego da forma correta
    async function submeterReserva(event) {
        event.preventDefault();
        
        const quadraSelecionadaRadio = document.querySelector('input[name="quadra-radio"]:checked');
        if (!quadraSelecionadaRadio) {
            alert("Erro: Nenhuma quadra selecionada.");
            return;
        }
        
        const reserva = {
            quadra_id: quadraSelecionadaRadio.value,
            data: dataSelecionada,
            horario: horarioSelecionado
        };

        try {
            const token = localStorage.getItem('accessToken');
            const response = await fetch('/api/reservas', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify(reserva)
            });

            if (response.ok) {
                alert('Reserva realizada com sucesso!');
                window.location.href = '/home.html';
            } else if (response.status === 401 || response.status === 403) {
                alert('Sua sessão expirou. Por favor, faça login novamente.');
                localStorage.removeItem('accessToken');
                localStorage.removeItem('userName');
                window.location.href = '/login.html';
            } else {
                const errorData = await response.json();
                alert(`Erro ao reservar: ${errorData.error || errorData.message}`);
            }
        } catch (error) {
            console.error('Erro ao submeter reserva:', error);
        }
    }

    // Adiciona os listeners de eventos
    verHorariosBtn.addEventListener('click', buscarHorarios);
    reservaForm.addEventListener('submit', submeterReserva);
    
    // Inicia o carregamento das quadras
    carregarQuadras();
});