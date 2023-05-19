--DROP ALL OBJECTS;

SET REFERENTIAL_INTEGRITY FALSE;

TRUNCATE TABLE CATALOGOS;
TRUNCATE TABLE CATALOGOS_VALORES;
TRUNCATE TABLE PERSONA;
TRUNCATE TABLE DENUNCIA;
TRUNCATE TABLE DENUNCIA_PERSONA;


SET REFERENTIAL_INTEGRITY TRUE;

--DROP TABLE IF EXISTS denuncia_persona;

---###############################
-- CATALOGOS
---###############################
INSERT INTO catalogos (ID_CATALOGO, DS_NOMBRE, TL_DESCRIPCION, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA) VALUES  (1, 'SEXO', 'GENERO M O F', 'N', 'ADMIN',  '2015-04-03 14:00:45');
INSERT INTO catalogos (ID_CATALOGO, DS_NOMBRE, TL_DESCRIPCION, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA) VALUES  (2, 'TIPO DE IDENTIFCACION', 'DNI U CARNET EXTRANGERIA', 'N', 'ADMIN',  now());
INSERT INTO catalogos (ID_CATALOGO, DS_NOMBRE, TL_DESCRIPCION, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA) VALUES  (3, 'ESTADO DE LA DENUNCIA', 'NULL', 'N', 'ADMIN',  now());
INSERT INTO catalogos (ID_CATALOGO, DS_NOMBRE, TL_DESCRIPCION, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA) VALUES  (4, 'TIPOS DE DOCUMENTO', 'NULL', 'N', 'ADMIN',  now());
INSERT INTO catalogos (ID_CATALOGO, DS_NOMBRE, TL_DESCRIPCION, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA) VALUES  (5, 'AUXILIAR', 'NULL', 'S', 'ADMIN',  now());
INSERT INTO catalogos (ID_CATALOGO, DS_NOMBRE, TL_DESCRIPCION, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA) VALUES  (6, 'TIPOS DE DELITOS', 'NULL', 'S', 'ADMIN',  now());
INSERT INTO catalogos (ID_CATALOGO, DS_NOMBRE, TL_DESCRIPCION, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA) VALUES  (7, 'UNIDADES SANCIONADORAS', 'UNID SANCIONADORA', 'S', 'ADMIN',  now());
INSERT INTO catalogos (ID_CATALOGO, DS_NOMBRE, TL_DESCRIPCION, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA) VALUES  (8, 'INSTITUCIÓN', 'NULL', 'S', 'ADMIN',  now());
INSERT INTO catalogos (ID_CATALOGO, DS_NOMBRE, TL_DESCRIPCION, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA) VALUES  (9, 'TIPO DENUNCIANTE', 'IDENTIFICA SI ES DENUNCIANTE O DENUNCIADO', 'S', 'ADMIN',  now());
INSERT INTO catalogos (ID_CATALOGO, DS_NOMBRE, TL_DESCRIPCION, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA) VALUES  (10, 'GRADO', 'GRADO DEL OFICIAL', 'S', 'ADMIN',  now());
INSERT INTO catalogos (ID_CATALOGO, DS_NOMBRE, TL_DESCRIPCION, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA) VALUES  (11, 'FISCALIA', 'FISCALIA', 'S', 'ADMIN',  now());
INSERT INTO catalogos (ID_CATALOGO, DS_NOMBRE, TL_DESCRIPCION, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA) VALUES  (12, 'MESA DE PARTE', 'MESA DE PARTE', 'S', 'ADMIN',  now());

---###############################
-- CATALOGOS_VALORES
---#################################
-- GENERO
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (1,'MASCULINO', 'M', 'N', 'ADMIN',  now(), 1);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (2, 'FEMENINO', 'F', 'N', 'ADMIN',  now(), 1);

-- TIPO DOCUMENTO INDENTIDAD
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (3, 'DNI', 'DNI', 'N', 'ADMIN',  now(), 2);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (4, 'CARNET DE EXTRANJERÍA', 'CE', 'N', 'ADMIN',  now(), 2);

-- estados de la denuncia
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (5, 'DENUNCIA', 'DCIA', 'N', 'ADMIN',  now(), 3);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (6, 'DEVOLVER', 'DVER', 'N', 'ADMIN',  now(), 3);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (7, 'DESESTIMAR', 'DST', 'N', 'ADMIN',  now(), 3);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (8, 'PRELIMINAR', 'PRM', 'N', 'ADMIN',  now(), 3);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (9, 'PREPARATORIA', 'PRPA', 'N', 'ADMIN',  now(), 3);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (10, 'REVISIÓN', 'RSION', 'N', 'ADMIN',  now(), 3);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (11, 'ARCHIVADO', 'ARCH', 'N', 'ADMIN',  now(), 3);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (12, 'OTROS', 'OTR', 'N', 'ADMIN',  now(), 3);

-- TIPOS DE DOCUMENTO TRAMITES
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (13, 'OFICIO', 'OFI', 'N', 'ADMIN',  now(), 4);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (14, 'INFORME', 'INF', 'N', 'ADMIN',  now(), 4);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (15, 'JUNTA', 'JTA', 'N', 'ADMIN',  now(), 4);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (16, 'RESOLUCIÓN', 'RES', 'N', 'ADMIN',  now(), 4);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (17, 'OTROS', 'OTR', 'N', 'ADMIN',  now(), 4);

-- AUXILIARES
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (18, 'AUXILIAR_1', 'AX1', 'N', 'ADMIN',  now(), 5);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (19, 'AUXILIAR_2', 'AX2', 'N', 'ADMIN',  now(), 5);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (20, 'AUXILIAR_3', 'AX3', 'N', 'ADMIN',  now(), 5);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (21, 'AUXILIAR_4', 'AX4', 'N', 'ADMIN',  now(), 5);

-- DELITOS
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (22, 'DESERCIÓN', 'DESC', 'N', 'ADMIN',  now(), 6);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (23, 'DESOBEDIENCIA', 'DESB', 'N', 'ADMIN',  now(), 6);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (24, 'INSULTO', 'INS', 'N', 'ADMIN',  now(), 6);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (25, 'ABUSO', 'ABU', 'N', 'ADMIN',  now(), 6);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (26, 'HURTO', 'HTO', 'N', 'ADMIN',  now(), 6);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (27, 'AFECTACIÓN', 'AFEC', 'N', 'ADMIN',  now(), 6);

-- UNIDADES SANCIONADORAS
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (28, 'COMANDANCIA GENERAL', 'COMGEN', 'N', 'ADMIN',  now(), 7);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (29, 'SETRA', 'SETRA', 'N', 'ADMIN',  now(), 7);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (30, 'BIM 2', 'BIM2', 'N', 'ADMIN',  now(), 7);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (31, 'INSPECTORÍA', 'INSP', 'N', 'ADMIN',  now(), 7);

-- INSTITUCIONES
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (32,'POLICÍA NACIONAL DEL PERÚ', 'PNP', 'N', 'ADMIN',  now(), 8);

-- TIPO DE DENUNCIANTES
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (33, 'DENUCIANTE', 'DNCTE', 'N', 'ADMIN',  now(), 9);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (34, 'DENUNCIADO', 'DNCDO', 'N', 'ADMIN',  now(), 9);

-- GRADO
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (35, 'TECNICO  DE PRIMERA', 'TC1', 'N', 'ADMIN',  now(), 10);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (36, 'TECNICO DE SEGUNDA', 'TC2', 'N', 'ADMIN',  now(), 10);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (37, 'TECNICO DE TERCERA', 'TC3', 'N', 'ADMIN',  now(), 10);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (38, 'CORONEL', 'CRNL', 'N', 'ADMIN',  now(), 10);

-- FISCALIA
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (39, 'FISCALÍA 13', '13', 'S', 'ADMIN',  now(), 11);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (40, 'FISCALÍA 14', '14', 'S', 'ADMIN',  now(), 11);


-- MESA DE PARTE
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (41, 'MESA DE PARTE 13', 'M13', 'S', 'ADMIN',  now(), 12);
INSERT INTO catalogos_valores (ID_VALOR, DS_VALOR, CD_CODIGO, IT_MANTENIBLE, CD_USU_ALTA, FC_ALTA_FILA, ID_CATALOGO) VALUES (42, 'MESA DE PARTE 14', 'M14', 'S', 'ADMIN',  now(), 12);






--DROP TABLE IF EXISTS persona;
--PERSONAS  T1
INSERT INTO PERSONA (ID_PERSONA, NOMBRE, APELLIDO1, APELLIDO2, DNI, ID_INSTITUCION, ID_GENERO, ID_GRADO, ID_TIPO_IDENTIFICACION)
                VALUES (1, 'GERARDO', 'CABRERA', 'SOTO', '45977922', 32, 1, 35, 3);
--  T2
INSERT INTO PERSONA (ID_PERSONA, NOMBRE, APELLIDO1, APELLIDO2, DNI, ID_INSTITUCION, ID_GENERO, ID_GRADO, ID_TIPO_IDENTIFICACION)
            VALUES (2, 'YOMAR', 'MANDRIL', 'PALACION', '45977923', 32, 1, 36, 3);

--  T3
INSERT INTO PERSONA (ID_PERSONA, NOMBRE, APELLIDO1, APELLIDO2, DNI, ID_INSTITUCION, ID_GENERO, ID_GRADO, ID_TIPO_IDENTIFICACION)
            VALUES (3, 'SERGIO', 'PEÑA', 'LUNA', '45977924', 32, 1, 37, 3);


--  CRNEL
INSERT INTO PERSONA (ID_PERSONA, NOMBRE, APELLIDO1, APELLIDO2, DNI, ID_INSTITUCION, ID_GENERO, ID_GRADO, ID_TIPO_IDENTIFICACION)
VALUES (4, 'MANUEL', 'SANTIÑAN', 'ROSCO', '45977925', 32, 1, 38, 3);


--###################################
--#  DENUNCIA                       #
--###################################
--DROP TABLE IF EXISTS DENUNCIA_PERSONA;
--DROP TABLE IF EXISTS denuncia;
INSERT INTO DENUNCIA (ID_DENUNCIA, NM_DENUNCIA, FC_ALTA_DENUNCIA, FC_HECHOS, ID_ESTADO,  ID_DELITO, ID_AUXILIAR, FC_PLAZO,  DS_DESCRIPCION, ID_TIPO_DOCUMENTO, NM_DOCUMENTO, FC_INGRESO_DOCUMENTO, ID_MESA_PARTE, ID_FISCALIA)
VALUES (1, 'DEN001-2023-13', CURRENT_TIMESTAMP, '2023-04-10', 5, 25, 18, '2023-05-10', 'Delito de abuso de autoridad xd', 14, 'DOC-001', '2023-04-16',  41, 39);


--###################################
--#  DENUNCIA_PERSONA               #
--###################################

/**
INSERT INTO DENUNCIA_PERSONA (ID_PERSONA, ID_DENUNCIA, ID_TIPO_PERSONA, FC_ALTA_DENUNCIA)
VALUES (1, 1, 33, CURRENT_TIMESTAMP);

INSERT INTO DENUNCIA_PERSONA (ID_PERSONA, ID_DENUNCIA, ID_TIPO_PERSONA, FC_ALTA_DENUNCIA)
VALUES (2, 1, 33, CURRENT_TIMESTAMP);

INSERT INTO DENUNCIA_PERSONA (ID_PERSONA, ID_DENUNCIA, ID_TIPO_PERSONA, FC_ALTA_DENUNCIA)
VALUES (4, 1, 34, CURRENT_TIMESTAMP);
**/

--select * from catalogos_valores;