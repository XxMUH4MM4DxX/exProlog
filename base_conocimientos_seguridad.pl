% ===============================================
% Sistema Experto: Diagnostico de Seguridad y Rendimiento de Servidores
% ===============================================

:- dynamic hecho/1.

% -----------------------------------------------
% Preguntas asociadas a los hechos
% -----------------------------------------------

preguntar(alta_tasa_intentos_login, 
    'El sistema ha identificado un volumen inusualmente alto de intentos de autenticacion en un corto periodo de tiempo? (s/n)').

preguntar(misma_ip_repetida, 
    'Se han detectado multiples intentos de acceso desde una misma direccion IP? (s/n)').

preguntar(usuarios_inexistentes_detectados, 
    'Se han registrado intentos de autenticacion con nombres de usuario inexistentes? (s/n)').

preguntar(tokens_invalidos, 
    'El sistema ha recibido tokens de autenticacion invalidos o malformados? (s/n)').

preguntar(tiempo_respuesta_lento, 
    'El servidor esta presentando tiempos de respuesta inusualmente altos? (s/n)').

preguntar(cpu_alta, 
    'El uso del CPU se mantiene consistentemente por encima del umbral normal? (s/n)').

preguntar(memoria_alta, 
    'El consumo de memoria RAM se encuentra en niveles criticos? (s/n)').

preguntar(usuarios_legitimos_activos, 
    'Hay una cantidad elevada de sesiones de usuarios legitimos activas simultaneamente? (s/n)').

% -----------------------------------------------
% Reglas de diagnostico
% -----------------------------------------------

regla(posible_fuerza_bruta, [alta_tasa_intentos_login, misma_ip_repetida, usuarios_inexistentes_detectados]).
regla(posible_ddos, [alta_tasa_intentos_login, tokens_invalidos, tiempo_respuesta_lento]).
regla(posible_sobrecarga_legitima, [cpu_alta, memoria_alta, usuarios_legitimos_activos]).
regla(requiere_escalado, [cpu_alta, memoria_alta, tiempo_respuesta_lento]).
regla(posible_actividad_sigilosa, [tokens_invalidos, usuarios_inexistentes_detectados, tiempo_respuesta_lento]).

% -----------------------------------------------
% Diagnóstico completo
% -----------------------------------------------

diagnosticar :-
    findall(Nombre-Regla, (regla(Nombre, Hechos), cumple_regla(Hechos)), ReglasCumplidas),
    (
        ReglasCumplidas \= [] ->
            nl, write('======================================'), nl,
            write('       RESULTADOS DEL DIAGNOSTICO     '), nl,
            write('======================================'), nl,
            mostrar_diagnosticos(ReglasCumplidas)
        ;
            nl, write('Diagnostico: SIN COINCIDENCIA EXACTA'), nl,
            write('No se detecto una amenaza concluyente. Los siguientes hechos fueron activados:'), nl,
            listar_hechos_activados,
            sugerencias_parciales
    ).

% Verifica si todos los hechos de una regla se cumplen
cumple_regla([]).
cumple_regla([H|T]) :-
    hecho(H),
    cumple_regla(T).

mostrar_diagnosticos([]).
mostrar_diagnosticos([Nombre-_|T]) :-
    mostrar_descripcion(Nombre),
    orientacion(Nombre),
    nl, mostrar_diagnosticos(T).

% -----------------------------------------------
% Orientaciones por diagnostico
% -----------------------------------------------

mostrar_descripcion(posible_fuerza_bruta) :-
    nl, write('Diagnostico de seguridad: POSIBLE ATAQUE DE FUERZA BRUTA DETECTADO'), nl,
    write('Descripcion: Multiples intentos fallidos de inicio de sesion desde una IP recurrente con usuarios inexistentes.'), nl.
mostrar_descripcion(posible_ddos) :-
    nl, write('Diagnostico de seguridad: POSIBLE ATAQUE DDoS'), nl,
    write('Descripcion: Alta tasa de accesos con tokens invalidos y lentitud del servidor sugiere una sobrecarga maliciosa.'), nl.
mostrar_descripcion(posible_sobrecarga_legitima) :-
    nl, write('Diagnostico de rendimiento: SOBRECARGA POR ACTIVIDAD LEGITIMA'), nl,
    write('Descripcion: Alta demanda de usuarios legitimos sin indicios de ataque.'), nl.
mostrar_descripcion(requiere_escalado) :-
    nl, write('Diagnostico de capacidad: REQUIERE ESCALADO DEL SERVIDOR'), nl,
    write('Descripcion: El uso excesivo de recursos y lentitud indica necesidad de escalar.'), nl.
mostrar_descripcion(posible_actividad_sigilosa) :-
    nl, write('Diagnostico de seguridad: POSIBLE ACTIVIDAD MALICIOSA SIGILOSA'), nl,
    write('Descripcion: Tokens invalidos y usuarios inexistentes junto a lentitud del sistema.'), nl.

orientacion(posible_fuerza_bruta) :-
    write('Recomendaciones:'), nl,
    write('- Implementar bloqueo temporal tras intentos fallidos.'), nl,
    write('- Usar CAPTCHA en login.'), nl,
    write('- Monitorear IPs sospechosas.'), nl.

orientacion(posible_ddos) :-
    write('Recomendaciones:'), nl,
    write('- Balanceadores de carga con proteccion contra DDoS.'), nl,
    write('- CDN y firewalls.'), nl.

orientacion(posible_sobrecarga_legitima) :-
    write('Recomendaciones:'), nl,
    write('- Habilitar escalado automatico.'), nl,
    write('- Optimizar bases de datos y cache.'), nl.

orientacion(requiere_escalado) :-
    write('Recomendaciones:'), nl,
    write('- Ampliar CPU/RAM del servidor.'), nl,
    write('- Balanceo de carga horizontal.'), nl.

orientacion(posible_actividad_sigilosa) :-
    write('Recomendaciones:'), nl,
    write('- Revisar actividad sospechosa.'), nl,
    write('- Activar IDS/IPS.'), nl.

% -----------------------------------------------
% Interacción con el usuario
% -----------------------------------------------

realizar_diagnostico :-
    retractall(hecho(_)),
    forall(preguntar(Hecho, Pregunta), (
        nl, write(Pregunta), nl,
        read(Respuesta),
        (Respuesta == s -> assertz(hecho(Hecho)) ; true)
    )),
    diagnosticar.

% -----------------------------------------------
% Muestra hechos activados
% -----------------------------------------------

listar_hechos_activados :-
    findall(H, hecho(H), Lista),
    forall(member(X, Lista), (
        write('- Hecho activado: '), write(X), nl
    )).

% -----------------------------------------------
% Sugerencias basadas en coincidencias parciales
% -----------------------------------------------

sugerencias_parciales :-
    findall(Nombre, (
        regla(Nombre, Requisitos),
        intersection(Requisitos, _, Coincidencias),
        Coincidencias \= [],
        member(C, Coincidencias), hecho(C)
    ), Posibles),
    sort(Posibles, Unicos),
    nl, write('Posibles amenazas relacionadas segun los sintomas detectados:'), nl,
    forall(member(R, Unicos), (
        write('- Posible amenaza: '), write(R), nl
    )).
