/* ============================================================
   NetPulse — lógica del panel de monitoreo
   Simula datos en tiempo real (sin backend). Reemplaza las
   funciones marcadas "// TODO backend" por llamadas reales.
   ============================================================ */

(function () {
  'use strict';

  // ---------- Estado de la aplicación ----------
  let dispositivos = [
    crearDispositivo('Router-Principal', 'Router', '192.168.1.1', 'online'),
    crearDispositivo('Servidor-Web', 'Servidor', '192.168.1.10', 'online'),
    crearDispositivo('Switch-Sala', 'Switch', '192.168.1.2', 'online'),
    crearDispositivo('Camara-Entrada', 'Cámara IP', '192.168.1.20', 'warning'),
    crearDispositivo('NAS-Backup', 'Almacenamiento', '192.168.1.15', 'online'),
    crearDispositivo('Laptop-Oficina', 'PC', '192.168.1.30', 'offline'),
  ];

  let alertas = [];
  let seleccionIndex = null;
  let alertasNoLeidas = 0;

  // ---------- Utilidades de datos ----------
  function crearDispositivo(nombre, tipo, ip, estadoForzado) {
    const estado = estadoForzado || elegir(['online', 'online', 'online', 'warning', 'offline']);
    const offline = estado === 'offline';
    return {
      id: 'd-' + Math.random().toString(36).slice(2, 9),
      nombre,
      tipo,
      ip,
      estado,
      cpu: offline ? 0 : aleatorio(15, 60),
      ram: offline ? 0 : aleatorio(20, 65),
      temp: offline ? 0 : aleatorio(38, 58),
      ultimaActualizacion: ahoraTexto(),
    };
  }

  function aleatorio(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
  function elegir(lista) { return lista[Math.floor(Math.random() * lista.length)]; }
  function ahoraTexto() {
    const d = new Date();
    return d.toLocaleTimeString('es-MX', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }
  function claseEstado(estado) {
    if (estado === 'online') return 'online';
    if (estado === 'warning') return 'warning';
    return 'offline';
  }
  function textoEstado(estado) {
    if (estado === 'online') return 'En línea';
    if (estado === 'warning') return 'Advertencia';
    return 'Desconectado';
  }

  function recalcularEstadoPorMetricas(d) {
    if (d.estado === 'offline') return;
    if (d.cpu >= 88 || d.ram >= 92 || d.temp >= 75) d.estado = 'warning';
    else d.estado = 'online';
  }

  // ---------- Referencias DOM ----------
  const pantallaBienvenida = document.getElementById('pantalla-bienvenida');
  const panelPrincipal = document.getElementById('panel-principal');
  const btnEmpezar = document.getElementById('btn-empezar');

  const navBtns = document.querySelectorAll('.nav-btn');
  const tabs = document.querySelectorAll('.tab-content');

  const tablaBody = document.querySelector('#tabla-dispositivos tbody');
  const emptyDispositivos = document.getElementById('empty-dispositivos');
  const statTotal = document.getElementById('stat-total');
  const statOnline = document.getElementById('stat-online');
  const statWarning = document.getElementById('stat-warning');
  const statOffline = document.getElementById('stat-offline');

  const contenedorAlertas = document.getElementById('contenedor-alertas');
  const emptyAlertas = document.getElementById('empty-alertas');
  const badgeAlertas = document.getElementById('badge-alertas');

  const gridEstado = document.getElementById('grid-estado');
  const emptyEstado = document.getElementById('empty-estado');

  const btnNuevo = document.getElementById('btn-nuevo');
  const btnNuevoEmpty = document.getElementById('btn-nuevo-empty');
  const btnReemplazar = document.getElementById('btn-reemplazar');
  const btnEliminar = document.getElementById('btn-eliminar');
  const btnPing = document.getElementById('btn-ping');
  const btnRefrescarMetricos = document.getElementById('btn-refrescar-metricos');
  const btnLimpiarAlertas = document.getElementById('btn-limpiar-alertas');

  const modal = document.getElementById('modal-form');
  const modalTitulo = document.getElementById('modal-titulo');
  const form = document.getElementById('form-dispositivo');
  const dispIndex = document.getElementById('disp-index');
  const txtNombre = document.getElementById('txt-nombre');
  const txtTipo = document.getElementById('txt-tipo');
  const txtIp = document.getElementById('txt-ip');
  const txtCpu = document.getElementById('txt-cpu');
  const txtRam = document.getElementById('txt-ram');
  const txtTemp = document.getElementById('txt-temp');
  const txtUptime = document.getElementById('txt-uptime');
  const txtEstado = document.getElementById('txt-estado');
  const btnEscanear = document.getElementById('btn-escanear');
  const btnCancelar = document.getElementById('btn-cancelar');

  const toast = document.getElementById('toast');
  const reloj = document.getElementById('reloj');

  // ---------- Navegación ----------
  btnEmpezar.addEventListener('click', () => {
    pantallaBienvenida.classList.add('hidden');
    panelPrincipal.classList.remove('hidden');
    renderTodo();
  });

  navBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      navBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const target = btn.dataset.target;
      tabs.forEach(t => t.classList.toggle('active', t.id === target));
      if (target === 'sec-alertas') {
        alertasNoLeidas = 0;
        actualizarBadgeAlertas();
      }
    });
  });

  // ---------- Reloj ----------
  function actualizarReloj() {
    reloj.textContent = new Date().toLocaleTimeString('es-MX');
  }
  setInterval(actualizarReloj, 1000);
  actualizarReloj();

  // ---------- Toast ----------
  let toastTimeout;
  function mostrarToast(mensaje) {
    toast.textContent = mensaje;
    toast.classList.remove('hidden');
    clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => toast.classList.add('hidden'), 2600);
  }

  // ---------- Render: tabla de dispositivos ----------
  function renderTabla() {
    tablaBody.innerHTML = '';
    emptyDispositivos.classList.toggle('hidden', dispositivos.length > 0);

    dispositivos.forEach((d, i) => {
      const tr = document.createElement('tr');
      tr.dataset.index = i;
      if (i === seleccionIndex) tr.classList.add('selected');
      tr.innerHTML = `
        <td class="col-select"><span class="row-radio"></span></td>
        <td>${escapeHtml(d.nombre)}</td>
        <td>${escapeHtml(d.tipo)}</td>
        <td class="ip-cell">${escapeHtml(d.ip)}</td>
        <td>
          <span class="status-pill ${claseEstado(d.estado)}">
            <span class="pulse-dot small ${d.estado === 'online' ? '' : d.estado}"></span>
            ${textoEstado(d.estado)}
          </span>
        </td>
      `;
      tr.addEventListener('click', () => seleccionarFila(i));
      tablaBody.appendChild(tr);
    });

    actualizarStats();
  }

  function seleccionarFila(i) {
    seleccionIndex = (seleccionIndex === i) ? null : i;
    btnReemplazar.disabled = seleccionIndex === null;
    btnEliminar.disabled = seleccionIndex === null;
    renderTabla();
  }

  function actualizarStats() {
    statTotal.textContent = dispositivos.length;
    statOnline.textContent = dispositivos.filter(d => d.estado === 'online').length;
    statWarning.textContent = dispositivos.filter(d => d.estado === 'warning').length;
    statOffline.textContent = dispositivos.filter(d => d.estado === 'offline').length;
  }

  // ---------- Render: métricas ----------
  function renderMetricas() {
    gridEstado.innerHTML = '';
    emptyEstado.classList.toggle('hidden', dispositivos.length > 0);

    dispositivos.forEach(d => {
      const card = document.createElement('div');
      card.className = 'metric-card';
      card.innerHTML = `
        <div class="metric-card-head">
          <div>
            <p class="metric-name">${escapeHtml(d.nombre)}</p>
            <span class="metric-ip">${escapeHtml(d.ip)}</span>
          </div>
          <span class="status-pill ${claseEstado(d.estado)}">
            <span class="pulse-dot small ${d.estado === 'online' ? '' : d.estado}"></span>
            ${textoEstado(d.estado)}
          </span>
        </div>
        <div class="gauges-row">
          ${gaugeSvg('CPU', d.cpu, colorMetrica(d.cpu, 88))}
          ${gaugeSvg('RAM', d.ram, colorMetrica(d.ram, 92))}
        </div>
        <div class="metric-row"><span>Temperatura</span><span>${d.estado === 'offline' ? '—' : d.temp + '°C'}</span></div>
        <div class="metric-row"><span>Última actualización</span><span>${d.ultimaActualizacion}</span></div>
      `;
      gridEstado.appendChild(card);
    });
  }

  function colorMetrica(valor, umbral) {
    if (valor >= umbral) return 'var(--critical)';
    if (valor >= umbral - 20) return 'var(--warning)';
    return 'var(--online)';
  }

  function gaugeSvg(etiqueta, valor, color) {
    const r = 32, c = 2 * Math.PI * r;
    const offset = c - (Math.min(valor, 100) / 100) * c;
    return `
      <div class="gauge">
        <svg width="80" height="80" viewBox="0 0 80 80">
          <circle class="gauge-track" cx="40" cy="40" r="${r}"></circle>
          <circle class="gauge-value" cx="40" cy="40" r="${r}"
            style="stroke:${color}; stroke-dasharray:${c}; stroke-dashoffset:${offset};"></circle>
        </svg>
        <span class="gauge-number">${valor}%</span>
        <div class="gauge-label">${etiqueta}</div>
      </div>
    `;
  }

  // ---------- Render: alertas ----------
  function renderAlertas() {
    contenedorAlertas.innerHTML = '';
    emptyAlertas.classList.toggle('hidden', alertas.length > 0);

    alertas.slice().reverse().forEach(a => {
      const div = document.createElement('div');
      div.className = 'alert-card ' + a.severidad;
      div.innerHTML = `
        <div class="alert-icon">${iconoAlerta(a.severidad)}</div>
        <div class="alert-body">
          <p class="alert-title">${escapeHtml(a.titulo)}</p>
          <p class="alert-desc">${escapeHtml(a.descripcion)}</p>
        </div>
        <span class="alert-time">${a.hora}</span>
      `;
      contenedorAlertas.appendChild(div);
    });
  }

  function iconoAlerta(severidad) {
    if (severidad === 'critical') {
      return '<svg viewBox="0 0 24 24" width="17" height="17" fill="none"><path d="M12 2 1 21h22L12 2Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M12 9v5M12 17.5v.1" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>';
    }
    if (severidad === 'warning') {
      return '<svg viewBox="0 0 24 24" width="17" height="17" fill="none"><path d="M12 8v5M12 16v.1" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8"/></svg>';
    }
    return '<svg viewBox="0 0 24 24" width="17" height="17" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8"/><path d="M12 8h.01M12 11v5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>';
  }

  function agregarAlerta(severidad, titulo, descripcion) {
    alertas.push({ severidad, titulo, descripcion, hora: ahoraTexto() });
    if (alertas.length > 40) alertas.shift();
    alertasNoLeidas++;
    actualizarBadgeAlertas();
    renderAlertas();
  }

  function actualizarBadgeAlertas() {
    badgeAlertas.textContent = alertasNoLeidas;
    badgeAlertas.classList.toggle('hidden', alertasNoLeidas === 0);
  }

  btnLimpiarAlertas.addEventListener('click', () => {
    alertasNoLeidas = 0;
    actualizarBadgeAlertas();
    mostrarToast('Alertas marcadas como leídas');
  });

  // ---------- Render general ----------
  function renderTodo() {
    renderTabla();
    renderMetricas();
    renderAlertas();
  }

  // ---------- Modal: nuevo / reemplazar ----------
  function abrirModal(indexExistente) {
    form.reset();
    txtCpu.value = ''; txtRam.value = ''; txtTemp.value = ''; txtUptime.value = ''; txtEstado.value = '';

    if (indexExistente !== null && indexExistente !== undefined) {
      const d = dispositivos[indexExistente];
      modalTitulo.textContent = 'Reemplazar dispositivo';
      dispIndex.value = indexExistente;
      txtNombre.value = d.nombre;
      txtTipo.value = d.tipo;
      txtIp.value = d.ip;
      txtCpu.value = d.cpu + '%';
      txtRam.value = d.ram + '%';
      txtTemp.value = d.temp + '°C';
      txtUptime.value = d.ultimaActualizacion;
      txtEstado.value = textoEstado(d.estado);
    } else {
      modalTitulo.textContent = 'Nuevo dispositivo';
      dispIndex.value = '';
    }
    modal.classList.remove('hidden');
    txtNombre.focus();
  }

  function cerrarModal() { modal.classList.add('hidden'); }

  btnNuevo.addEventListener('click', () => abrirModal(null));
  btnNuevoEmpty.addEventListener('click', () => abrirModal(null));
  btnReemplazar.addEventListener('click', () => {
    if (seleccionIndex !== null) abrirModal(seleccionIndex);
  });
  btnCancelar.addEventListener('click', cerrarModal);
  modal.addEventListener('click', (e) => { if (e.target === modal) cerrarModal(); });

  btnEliminar.addEventListener('click', () => {
    if (seleccionIndex === null) return;
    const d = dispositivos[seleccionIndex];
    if (!confirm(`¿Eliminar "${d.nombre}" (${d.ip}) del monitoreo?`)) return;
    dispositivos.splice(seleccionIndex, 1);
    seleccionIndex = null;
    btnReemplazar.disabled = true;
    btnEliminar.disabled = true;
    renderTodo();
    mostrarToast('Dispositivo eliminado');
  });

  // ---------- Escaneo automático (simulado) ----------
  // TODO backend: reemplazar por una llamada real que consulte el dispositivo en txtIp.value
  btnEscanear.addEventListener('click', () => {
    if (!txtIp.value.trim()) {
      mostrarToast('Ingresa una IP antes de escanear');
      return;
    }
    btnEscanear.disabled = true;
    btnEscanear.textContent = 'Escaneando...';

    setTimeout(() => {
      const enLinea = Math.random() > 0.15;
      const cpu = enLinea ? aleatorio(15, 70) : 0;
      const ram = enLinea ? aleatorio(20, 70) : 0;
      const temp = enLinea ? aleatorio(38, 62) : 0;

      txtCpu.value = enLinea ? cpu + '%' : '—';
      txtRam.value = enLinea ? ram + '%' : '—';
      txtTemp.value = enLinea ? temp + '°C' : '—';
      txtUptime.value = ahoraTexto();
      txtEstado.value = enLinea ? 'En línea' : 'Desconectado';

      form.dataset.cpu = cpu;
      form.dataset.ram = ram;
      form.dataset.temp = temp;
      form.dataset.estado = enLinea ? 'online' : 'offline';

      btnEscanear.disabled = false;
      btnEscanear.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none"><circle cx="11" cy="11" r="7" stroke="currentColor" stroke-width="1.8"/><path d="m20 20-3.5-3.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg> Escanear dispositivo (auto)';
      mostrarToast(enLinea ? 'Dispositivo detectado' : 'El dispositivo no respondió');
    }, 900);
  });

  // ---------- Guardar dispositivo ----------
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const nombre = txtNombre.value.trim();
    const tipo = txtTipo.value.trim();
    const ip = txtIp.value.trim();
    const idx = dispIndex.value;

    const datos = {
      nombre, tipo, ip,
      cpu: form.dataset.cpu !== undefined ? Number(form.dataset.cpu) : aleatorio(15, 60),
      ram: form.dataset.ram !== undefined ? Number(form.dataset.ram) : aleatorio(20, 65),
      temp: form.dataset.temp !== undefined ? Number(form.dataset.temp) : aleatorio(38, 58),
      estado: form.dataset.estado || 'online',
      ultimaActualizacion: ahoraTexto(),
    };

    if (idx !== '') {
      dispositivos[Number(idx)] = { ...dispositivos[Number(idx)], ...datos };
      mostrarToast('Dispositivo actualizado');
    } else {
      dispositivos.push({ id: 'd-' + Math.random().toString(36).slice(2, 9), ...datos });
      mostrarToast('Dispositivo agregado');
    }

    delete form.dataset.cpu; delete form.dataset.ram; delete form.dataset.temp; delete form.dataset.estado;
    seleccionIndex = null;
    btnReemplazar.disabled = true;
    btnEliminar.disabled = true;
    cerrarModal();
    renderTodo();
  });

  // ---------- Probar conexión (ping) ----------
  // TODO backend: reemplazar por una petición real de ping a cada IP
  btnPing.addEventListener('click', () => {
    const objetivo = seleccionIndex !== null ? [dispositivos[seleccionIndex]] : dispositivos;
    if (objetivo.length === 0) { mostrarToast('No hay dispositivos para probar'); return; }

    btnPing.disabled = true;
    const textoOriginal = btnPing.innerHTML;
    btnPing.innerHTML = 'Enviando ping...';

    setTimeout(() => {
      objetivo.forEach(d => {
        const responde = Math.random() > 0.2;
        const estadoAnterior = d.estado;
        d.estado = responde ? (Math.random() > 0.85 ? 'warning' : 'online') : 'offline';
        d.ultimaActualizacion = ahoraTexto();
        if (responde) {
          d.cpu = aleatorio(15, 70); d.ram = aleatorio(20, 70); d.temp = aleatorio(38, 62);
        } else {
          d.cpu = 0; d.ram = 0; d.temp = 0;
        }
        if (estadoAnterior !== 'offline' && d.estado === 'offline') {
          agregarAlerta('critical', `${d.nombre} no responde`, `Sin respuesta de ping en ${d.ip}.`);
        } else if (estadoAnterior === 'offline' && d.estado !== 'offline') {
          agregarAlerta('info', `${d.nombre} reconectado`, `El dispositivo volvió a responder en ${d.ip}.`);
        }
      });
      btnPing.disabled = false;
      btnPing.innerHTML = textoOriginal;
      renderTodo();
      mostrarToast(`Ping completado (${objetivo.length} equipo${objetivo.length > 1 ? 's' : ''})`);
    }, 1000);
  });

  // ---------- Actualizar métricas manualmente ----------
  btnRefrescarMetricos.addEventListener('click', () => {
    simularCicloMetricas();
    mostrarToast('Métricas actualizadas');
  });

  // ---------- Simulación de tiempo real ----------
  function simularCicloMetricas() {
    dispositivos.forEach(d => {
      if (d.estado === 'offline') {
        // pequeña probabilidad de reconexión espontánea
        if (Math.random() < 0.08) {
          d.estado = 'online';
          d.cpu = aleatorio(15, 50); d.ram = aleatorio(20, 55); d.temp = aleatorio(38, 55);
          agregarAlerta('info', `${d.nombre} reconectado`, `El dispositivo volvió a estar disponible en ${d.ip}.`);
        }
        return;
      }
      // fluctuación natural
      d.cpu = clamp(d.cpu + aleatorio(-8, 8), 5, 99);
      d.ram = clamp(d.ram + aleatorio(-5, 6), 10, 99);
      d.temp = clamp(d.temp + aleatorio(-2, 3), 30, 90);
      d.ultimaActualizacion = ahoraTexto();

      const estadoPrevio = d.estado;
      recalcularEstadoPorMetricas(d);

      if (estadoPrevio !== 'warning' && d.estado === 'warning') {
        if (d.cpu >= 88) agregarAlerta('warning', `CPU alto en ${d.nombre}`, `Uso de CPU en ${d.cpu}%, por encima del umbral seguro.`);
        else if (d.ram >= 92) agregarAlerta('warning', `RAM alta en ${d.nombre}`, `Uso de RAM en ${d.ram}%, por encima del umbral seguro.`);
        else if (d.temp >= 75) agregarAlerta('critical', `Temperatura elevada en ${d.nombre}`, `Se detectaron ${d.temp}°C. Revisa la ventilación del equipo.`);
      }

      // pequeña probabilidad de caída espontánea
      if (Math.random() < 0.015) {
        d.estado = 'offline';
        d.cpu = 0; d.ram = 0; d.temp = 0;
        agregarAlerta('critical', `${d.nombre} se desconectó`, `Se perdió la señal del dispositivo en ${d.ip}.`);
      }
    });
    renderTodo();
  }

  function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // Ciclo de "tiempo real": cada 5s se refrescan métricas y posibles alertas
  setInterval(simularCicloMetricas, 5000);

})();