% Declarar que hecho/1 es un predicado dinamico
:- dynamic hecho/1.

% -----------------------------
% Preguntas asociadas a los hechos
% -----------------------------

preguntar(alta_tasa_intentos_login, 
    'El sistema ha identificado un volumen inusualmente alto de intentos de autenticacion en un corto periodo de tiempo?. --porfavor confirme este comportamiento anomalo-- (s/n)').

preguntar(misma_ip_repetida, 
    'Se ha detectado una recurrencia significativa de intentos de acceso desde una misma direccion IP?. --porfavor valide este patron de comportamiento potencialmente malicioso-- (s/n)').

preguntar(usuarios_inexistentes_detectados, 
    'Se han registrado intentos de autenticacion con nombres de usuario que no corresponden a ninguna cuenta activa?. --porfavor Confirme la presencia de este tipo de actividad-- (s/n)').

preguntar(tokens_invalidos, 
    'El sistema ha interceptado solicitudes con tokens de autenticacion que no cumplen con los criterios de validez?. --porfavor confirma esta deteccion si es el caso (s/n)').

preguntar(tiempo_respuesta_lento, 
    'Se ha observado un incremento en la latencia de respuesta del servidor?. --porfavor valide que el sistema presenta tiempos de respuesta anormalmente elevados-- (s/n)').

preguntar(cpu_alta, 
    'Los indicadores de rendimiento muestran un uso sostenido del CPU por encima del umbral esperado?. --porfavor confirmar que el procesador esta operando en condiciones de alta carga-- (s/n)').

preguntar(memoria_alta, 
    'El consumo de memoria del servidor se encuentra en niveles criticos?. --porfavor validar que la memoria RAM esta siendo utilizada intensivamente-- (s/n)').

preguntar(usuarios_legitimos_activos, 
    'El sistema registra una cantidad considerable de sesiones autenticas activas simultaneamente?. --porfavor comfirme que se trata de trafico legitimo autorizado-- (s/n)').


% -----------------------------
% Reglas de diagnostico
% -----------------------------

% Regla 1: Fuerza bruta
regla(posible_fuerza_bruta) :-
    hecho(alta_tasa_intentos_login),
    hecho(misma_ip_repetida),
    hecho(usuarios_inexistentes_detectados).

% Regla 2: Ataque DDoS
regla(posible_ddos) :-
    hecho(alta_tasa_intentos_login),
    hecho(tokens_invalidos),
    hecho(tiempo_respuesta_lento).

% Regla 3: Sobrecarga legitima
regla(posible_sobrecarga_legitima) :-
    hecho(cpu_alta),
    hecho(memoria_alta),
    hecho(usuarios_legitimos_activos).

% Regla 4: Servidor requiere escalar
regla(requiere_escalado) :-
    hecho(cpu_alta),
    hecho(memoria_alta),
    hecho(tiempo_respuesta_lento).

% Regla 5: Actividad maliciosa 
regla(posible_actividad_sigilosa) :-
    hecho(tokens_invalidos),
    hecho(usuarios_inexistentes_detectados),
    hecho(tiempo_respuesta_lento).

% -----------------------------
% Motor de inferencia profesional
% -----------------------------

diagnosticar :-
    ( regla(posible_fuerza_bruta) ->
        nl, write('----Diagnostico de seguridad: **POSIBLE ATAQUE DE FUERZA BRUTA DETECTADO**----'), nl,
        write('Descripcion: El patron de actividad indica multiples intentos fallidos de inicio de sesion desde una IP recurrente, con usuarios no validos.'), nl, nl,
        orientacion(posible_fuerza_bruta)

    ; regla(posible_ddos) ->
        nl, write('----Diagnostico de seguridad: **POSIBLE ATAQUE DISTRIBUIDO DE DENEGACION DE SERVICIO (DDoS)**----'), nl,
        write('Descripcion: Alta tasa de accesos junto a tokens invalidos y latencia elevada sugieren una sobrecarga maliciosa del servidor.'), nl, nl,
        orientacion(posible_ddos)

    ; regla(posible_sobrecarga_legitima) ->
        nl, write('----Diagnostico de rendimiento: **SOBRECARGA DEL SISTEMA DEBIDA A ALTA ACTIVIDAD LEGITIMA**----'), nl,
        write('Descripcion: El sistema opera bajo una alta demanda justificada por usuarios validos. No se detectan patrones maliciosos.'), nl, nl,
        orientacion(posible_sobrecarga_legitima)

    ; regla(requiere_escalado) ->
        nl, write('----Diagnostico de capacidad: **EL SERVIDOR REQUIERE ESCALADO DE RECURSOS**----'), nl,
        write('Descripcion: Se detecta uso critico de CPU y RAM junto a latencia, lo cual sugiere que la infraestructura es insuficiente.'), nl, nl,
        orientacion(requiere_escalado)

    ; regla(posible_actividad_sigilosa) ->
        nl, write('----Diagnostico de seguridad: **ACTIVIDAD MALICIOSA POSIBLEMENTE SIGILOSA DETECTADA**----'), nl,
        write('Descripcion: Se han detectado indicios de un comportamiento malicioso que evade mecanismos tradicionales'), nl, nl,
        orientacion(posible_actividad_sigilosa)

    ;   nl, write('----Diagnostico: **SIN COINCIDENCIA EXACTA**----'), nl,
        write('No se ha detectado una amenaza clara, pero hay hechos activados que coinciden parcialmente.'), nl,
        findall(H, hecho(H), Hechos),
        listar_sugerencias_parciales(Hechos)
    ).

% -----------------------------
% Orientaciones por diagnostico
% -----------------------------

orientacion(posible_fuerza_bruta) :-
    write('Recomendaciones tecnicas:'), nl,
    write('- Aplicar politicas de bloqueo temporal tras multiples intentos fallidos.'), nl,
    write('- Integrar reCAPTCHA en los formularios de autenticacion.'), nl,
    write('- Monitorear y auditar los registros de acceso en tiempo real.'), nl.

orientacion(posible_ddos) :-
    write('Recomendaciones tecnicas:'), nl,
    write('- Implementar balanceadores de carga con proteccion contra DDoS.'), nl,
    write('- Utilizar servicios de CDN con filtrado de trafico malicioso.'), nl,
    write('- Configurar reglas de firewall para limitar accesos por IP y rango.'), nl.

orientacion(posible_sobrecarga_legitima) :-
    write('Recomendaciones tecnicas:'), nl,
    write('- Evaluar la posibilidad de autoescalado de recursos.'), nl,
    write('- Optimizar consultas a base de datos y cache de contenido.'), nl,
    write('- Implementar herramientas de monitoreo para anticipar picos de trafico.'), nl.

orientacion(requiere_escalado) :-
    write('Recomendaciones tecnicas:'), nl,
    write('- Incrementar la capacidad de CPU y memoria RAM del servidor.'), nl,
    write('- Analizar la migracion hacia una arquitectura basada en microservicios o contenedores.'), nl,
    write('- Aplicar practicas de balanceo de carga horizontal.'), nl.

orientacion(posible_actividad_sigilosa) :-
    write('Recomendaciones tecnicas:'), nl,
    write('- Investigar la posibilidad de exploits avanzados dirigidos a la capa de autenticacion.'), nl,
    write('- Revisar integridad de librerias, sesiones activas y verificar logs de seguridad mas alla del acceso web.'), nl,
    write('- Activar alertas tempranas y sistemas de deteccion de intrusos (IDS).'), nl.

% -----------------------------
% Interfaz con el usuario
% -----------------------------

realizar_diagnostico :-
    retractall(hecho(_)),  % Borra hechos previos
    forall(preguntar(Hecho, Pregunta), (
        write(Pregunta), nl,
        read(Respuesta),
        (Respuesta == s -> assertz(hecho(Hecho)) ; true)
    )),
    nl, write('--- Resultados del Diagnostico ---'), nl,
    diagnosticar.

% -----------------------------
% Listar hechos parciales
% -----------------------------

listar_sugerencias_parciales([]).
listar_sugerencias_parciales([H|T]) :-
    write('- Hecho activado: '), write(H), nl,
    listar_sugerencias_parciales(T).
