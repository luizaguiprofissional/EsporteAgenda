document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('accessToken');
    if (!token) {
        alert('Você precisa estar logado para agendar uma quadra.');
        window.location.href = '/login.html';
        return;
    }

    // --- Elementos do DOM ---
    const quadrasContainer = document.getElementById('quadras-list-container');
    const dataInput = document.getElementById('data-input'); // Agora controlado pelo Flatpickr
    const verHorariosBtn = document.getElementById('ver-horarios-btn');
    const horariosContainer = document.getElementById('horarios-container');
    const horariosSection = document.getElementById('horarios-disponiveis');
    const revisaoSection = document.getElementById('revisao-reserva');
    const listaSelecionados = document.getElementById('horarios-selecionados-lista');
    const confirmarBtn = document.getElementById('confirmar-reservas-btn');
    const statusReserva = document.getElementById('reserva-status');

    let datasSelecionadas = []; // Guarda as datas (AAAA-MM-DD)
    let horariosComunsSelecionados = []; // Guarda apenas os horários (HH:MM) comuns escolhidos
    let quadraInfoSelecionada = null; // Guarda { id, nome } da quadra

    // --- 1. Inicializar o Flatpickr ---
    const fp = flatpickr(dataInput, {
        mode: "multiple", // Permite selecionar múltiplas datas
        dateFormat: "Y-m-d", // Formato que o backend espera
        minDate: "today", // Não permite selecionar datas passadas
        locale: "pt", // Usa a tradução
        onChange: function(selectedDates) {
            // Guarda as datas selecionadas formatadas
            datasSelecionadas = selectedDates.map(date => date.toISOString().split('T')[0]);
            // Limpa horários e seleção se as datas mudarem
            horariosSection.classList.add('hidden');
            horariosComunsSelecionados = [];
            // Desmarca botões de horário visualmente
             document.querySelectorAll('.horario-btn.selecionado').forEach(btn => btn.classList.remove('selecionado'));
            atualizarListaSelecionados();
        }
    });

    // --- 2. Função carregarQuadras ---
    async function carregarQuadras() {
        try {
            const response = await fetch('/api/quadras');
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const data = await response.json();

            quadrasContainer.innerHTML = '';
            data.quadras.forEach(quadra => {
                const imagemSrc = quadra.imagem_url && quadra.imagem_url.startsWith('/') ? quadra.imagem_url : `/uploads/${quadra.imagem_url}`; // Ajuste para uploads
                const courtItemHTML = `
                    <label class="court-item" for="quadra-${quadra.id}">
                        <input type="radio" name="quadra-radio" id="quadra-${quadra.id}" value="${quadra.id}" class="court-radio">
                        <img src="${imagemSrc}" alt="${quadra.nome}" onerror="this.src='/assets/images/placeholder.jpg';"> <div class="court-item-info">
                            <h3 class="court-name">${quadra.nome}</h3>
                            <p>${quadra.tipo}</p>
                        </div>
                    </label>
                `;
                quadrasContainer.innerHTML += courtItemHTML;
            });

            document.querySelectorAll('.court-item').forEach(item => {
                item.addEventListener('click', () => {
                    document.querySelectorAll('.court-item').forEach(i => i.classList.remove('selected'));
                    item.classList.add('selected');
                    const radio = item.querySelector('.court-radio');
                    quadraInfoSelecionada = {
                        id: radio.value,
                        nome: item.querySelector('.court-name').textContent
                    };
                    horariosSection.classList.add('hidden');
                    horariosComunsSelecionados = [];
                     document.querySelectorAll('.horario-btn.selecionado').forEach(btn => btn.classList.remove('selecionado'));
                    atualizarListaSelecionados();
                    fp.clear(); // Limpa as datas ao trocar de quadra
                    datasSelecionadas = [];
                });
            });

            const urlParams = new URLSearchParams(window.location.search);
            const quadraIdFromUrl = urlParams.get('quadra');
            if (quadraIdFromUrl) {
                const radioToSelect = document.getElementById(`quadra-${quadraIdFromUrl}`);
                if (radioToSelect) {
                    radioToSelect.checked = true;
                    // Simular clique para garantir estado correto
                    radioToSelect.closest('.court-item').click();
                }
            }

        } catch (error) {
            console.error('Erro ao carregar quadras:', error);
            quadrasContainer.innerHTML = '<p style="color:red;">Não foi possível carregar as quadras. Verifique a conexão.</p>';
        }
    }

    // --- 3. Função buscarHorariosComuns ---
    async function buscarHorariosComuns() {
        if (!quadraInfoSelecionada || datasSelecionadas.length === 0) {
            alert('Por favor, selecione uma quadra e pelo menos uma data.');
            return;
        }

        horariosComunsSelecionados = [];
        atualizarListaSelecionados();
        horariosContainer.innerHTML = '<p>Buscando horários comuns...</p>';
        horariosSection.classList.remove('hidden');

        try {
            const response = await fetch('/api/horarios-multi', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}` // Garante que está enviando o token
                },
                body: JSON.stringify({ quadraId: quadraInfoSelecionada.id, dates: datasSelecionadas })
            });

            if (!response.ok) {
                 const errorData = await response.json().catch(() => ({ message: 'Erro desconhecido ao buscar horários.' }));
                 throw new Error(errorData.message || `Falha ao buscar horários (${response.status})`);
            }

            const data = await response.json();
            horariosContainer.innerHTML = '';

            if (data.horariosComuns.length === 0) {
                horariosContainer.innerHTML = '<p>Nenhum horário comum disponível para TODAS as datas selecionadas.</p>';
            } else {
                data.horariosComuns.forEach(horario => {
                    const btn = document.createElement('button');
                    btn.textContent = horario;
                    btn.classList.add('horario-btn');
                    btn.dataset.horario = horario;
                    btn.onclick = () => toggleSelecaoHorarioComum(btn);
                    horariosContainer.appendChild(btn);
                });
            }
        } catch (error) {
            console.error('Erro ao buscar horários comuns:', error);
            horariosContainer.innerHTML = `<p style="color:red;">Erro ao buscar horários: ${error.message}. Tente novamente.</p>`;
        }
    }

    // --- 4. Função toggleSelecaoHorarioComum ---
    function toggleSelecaoHorarioComum(botaoClicado) {
        const horario = botaoClicado.dataset.horario;
        const index = horariosComunsSelecionados.indexOf(horario);

        if (index > -1) {
            horariosComunsSelecionados.splice(index, 1);
            botaoClicado.classList.remove('selecionado');
        } else {
            horariosComunsSelecionados.push(horario);
            botaoClicado.classList.add('selecionado');
        }
        atualizarListaSelecionados();
    }

    // --- 5. Função atualizarListaSelecionados ---
    function atualizarListaSelecionados() {
        listaSelecionados.innerHTML = '';
        if (horariosComunsSelecionados.length === 0 || datasSelecionadas.length === 0 || !quadraInfoSelecionada) {
            listaSelecionados.innerHTML = '<li>Nenhum horário selecionado.</li>';
            revisaoSection.classList.add('hidden');
        } else {
            const datasOrdenadas = [...datasSelecionadas].sort((a, b) => new Date(a) - new Date(b));
            const horariosOrdenados = [...horariosComunsSelecionados].sort();

            datasOrdenadas.forEach(data => {
                const dataFormatada = new Date(data + 'T00:00:00').toLocaleDateString('pt-BR', { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' });
                let horariosHtml = horariosOrdenados.map(h => `<strong>${h}</strong>`).join(', ');

                listaSelecionados.innerHTML += `
                    <li style="border-bottom: 1px dashed #eee; padding-bottom: 10px; margin-bottom: 10px;">
                        <strong>${quadraInfoSelecionada.nome}</strong> - ${dataFormatada} <br>
                        <span style="font-size: 0.9em; color: #555;">Horários: ${horariosHtml}</span>
                    </li>`;
            });
            revisaoSection.classList.remove('hidden');
        }
        statusReserva.textContent = ''; // Limpa status anterior
    }

    // --- 6. Função enviarReservas ---
    async function enviarReservas() {
        if (horariosComunsSelecionados.length === 0 || datasSelecionadas.length === 0 || !quadraInfoSelecionada) {
            alert("Nenhuma combinação de data/horário selecionada ou quadra não definida.");
            return;
        }

        const dadosParaEnviar = [];
        datasSelecionadas.forEach(data => {
            horariosComunsSelecionados.forEach(horario => {
                dadosParaEnviar.push({
                    quadra_id: quadraInfoSelecionada.id,
                    data: data,
                    horario: horario
                });
            });
        });

        if (dadosParaEnviar.length === 0) {
             alert("Erro ao montar a lista de reservas para envio.");
             return;
        }

        statusReserva.textContent = 'Enviando reservas...';
        statusReserva.style.color = '#333';
        confirmarBtn.disabled = true;

        try {
            const response = await fetch('/api/reservas', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ reservas: dadosParaEnviar })
            });

            const result = await response.json(); // Tenta ler JSON mesmo em erro

            if (response.ok) {
                 statusReserva.textContent = 'Reservas realizadas com sucesso!';
                 statusReserva.style.color = 'green';
                 alert('Reservas realizadas com sucesso!');
                 // Limpa seleções após sucesso
                 horariosComunsSelecionados = [];
                 fp.clear();
                 datasSelecionadas = [];
                 horariosSection.classList.add('hidden');
                 revisaoSection.classList.add('hidden');
                 document.querySelectorAll('.horario-btn.selecionado').forEach(btn => btn.classList.remove('selecionado'));

            } else {
                 let errorMsg = result.message || `Falha na requisição (${response.status})`;
                 if(result.details) {
                     const falhas = result.details.filter(d => !d.success);
                     if (falhas.length > 0) {
                          // Formata detalhes do erro de forma mais clara
                         errorMsg += " Detalhes: " + falhas.map(f => `${new Date(f.data+'T00:00:00').toLocaleDateString('pt-BR')} ${f.horario} (${f.message})`).join('; ');
                     }
                 }
                 statusReserva.textContent = `Erro: ${errorMsg}`;
                 statusReserva.style.color = 'red';
                 alert(`Erro ao reservar: ${errorMsg}`);
                 // Ação pós-erro: Recarrega horários comuns e limpa seleção atual
                 buscarHorariosComuns(); // Atualiza a lista de disponíveis
                 horariosComunsSelecionados = []; // Limpa os horários que o usuário tinha clicado
                 document.querySelectorAll('.horario-btn.selecionado').forEach(btn => btn.classList.remove('selecionado')); // Desmarca visualmente
                 atualizarListaSelecionados(); // Atualiza a seção de revisão (que ficará vazia)
            }
        } catch (error) {
            statusReserva.textContent = 'Erro de conexão ao enviar reservas.';
            statusReserva.style.color = 'red';
            console.error('Erro de rede ou JSON inválido:', error);
            alert('Erro de conexão. Verifique sua internet e tente novamente.');
        } finally {
             confirmarBtn.disabled = false; // Reabilita o botão
        }
    }

    // --- Adiciona os listeners de eventos ---
    verHorariosBtn.addEventListener('click', buscarHorariosComuns);
    confirmarBtn.addEventListener('click', enviarReservas);

    // --- Inicia o carregamento das quadras ---
    carregarQuadras();
});

// --- Função logout (Manter) ---
function logout() {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('userName');
    window.location.href = '/login.html';
}