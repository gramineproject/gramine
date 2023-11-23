/* Copyright (C) 2023 Gramine contributors
 * SPDX-License-Identifier: BSD-3-Clause */

DROP TABLE IF EXISTS tab;

CREATE TABLE tab (
   id INTEGER,
   str TEXT
);

INSERT INTO tab (id, str) VALUES (1, ''), (2, ''), (3, ''), (4, '');
