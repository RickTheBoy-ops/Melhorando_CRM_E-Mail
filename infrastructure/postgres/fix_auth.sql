-- Script para corrigir autenticação do BillionMail
-- Garantir que o usuário admin existe e tem as credenciais corretas

-- Primeiro, vamos garantir que existe um usuário admin
INSERT INTO account (username, password, email, status, language, last_login_time, create_time, update_time)
VALUES ('admin', '$2b$12$U2V6kDGxPJchKCyotLlEqueLEIxo2oEphLC5o.Dr3JILV20TKibFW', 'admin@billionmail.com', 1, '', 0, extract(epoch from now())::int, extract(epoch from now())::int)
ON CONFLICT (account_id) DO UPDATE SET
    username = 'admin',
    password = '$2b$12$U2V6kDGxPJchKCyotLlEqueLEIxo2oEphLC5o.Dr3JILV20TKibFW',
    email = 'admin@billionmail.com',
    status = 1,
    update_time = extract(epoch from now())::int;

-- Se não houver conflito por account_id, vamos atualizar por email
UPDATE account SET 
    username = 'admin',
    password = '$2b$12$U2V6kDGxPJchKCyotLlEqueLEIxo2oEphLC5o.Dr3JILV20TKibFW',
    status = 1,
    update_time = extract(epoch from now())::int
WHERE email = 'admin@billionmail.com' AND username IS NULL OR username = '';

-- Verificar se o usuário foi criado/atualizado
SELECT account_id, username, email, status FROM account WHERE username = 'admin';