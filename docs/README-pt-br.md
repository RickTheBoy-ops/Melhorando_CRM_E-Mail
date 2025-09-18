<div align="center">
  <a name="readme-top"></a>
  <h1><a href="https://www.billionmail.com/" target="_blank">BillionMail 📧</a></h1>


## Uma Solução Open-Source de Servidor de Email, Boletim Informativo e Marketing por Email para Campanhas Mais Inteligentes

[![][license-shield]][license-link] [![][docs-shield]][docs-link] [![][github-release-shield]][github-release-link] [![][github-stars-shield]][github-stars-link]

[English](README.md) | [简体中文](README-zh_CN.md) | [日本語](README-ja.md) | [Deutsch](README-de.md) | Português (Brasil)
</div>
<br/>

<div align="center">
<a href="https://trendshift.io/repositories/13842" target="_blank"><img src="https://trendshift.io/api/badge/repositories/13842" alt="aaPanel%2FBillionMail | Trendshift" style="width: 250px; height: 55px;" width="250" height="55"/></a>
</div>

## O que é o BillionMail?

O BillionMail é uma **futura plataforma open-source de servidor de email e marketing por email** projetada para ajudar empresas e indivíduos a gerenciar suas campanhas de email com facilidade. Seja enviando boletins informativos, emails promocionais ou mensagens transacionais, esta ferramenta fornecerá **controle total** sobre seus esforços de marketing por email. Com recursos como **análises avançadas** e **gerenciamento de clientes**, você poderá criar, enviar e rastrear emails como um profissional.

![BillionMail Banner](https://www.billionmail.com/home.png?v1)

# Apenas 3 passos para enviar um bilhão de emails!
**Um bilhão de emails. Qualquer negócio. Garantido.**

### Passo 1️⃣ Instalar o BillionMail: 
✅ Leva **apenas 8️⃣ minutos** da instalação ao **✅ envio bem-sucedido de email**
```shell
cd /opt && git clone https://github.com/aaPanel/BillionMail && cd BillionMail && bash install.sh
```


### Passo 2️⃣: Conectar Seu Domínio
- Adicionar o domínio de envio
- Verificar registros DNS
- Habilitar SSL gratuito automaticamente


### Passo 3️⃣: Construir Sua Campanha

- Escrever ou colar seu email
- Escolher lista e tags
- Definir horário de envio ou enviar agora


<div align="center">
  <a href="https://www.youtube.com/embed/UHgxZa_9jGs?si=0-f1B5hDtcWImvQv" target="_blank">
    <img src="https://img.youtube.com/vi/UHgxZa_9jGs/maxresdefault.jpg" alt="" width="80%">
    <br />
    <img src="https://www.iconfinder.com/icons/317714/download/png/16" alt="YouTube" width="16"/>
    <b>Assistir no YouTube</b>
  </a>
</div>


## Outros métodos de instalação

### Instalação com um clique no aaPanel
👉 https://www.aapanel.com/new/download.html  (Faça login no ✅aaPanel --> 🐳Docker --> 1️⃣Instalação com um clique)




**Docker**
```shell
cd /opt && git clone https://github.com/aaPanel/BillionMail && cd BillionMail && cp env_init .env && docker compose up -d || docker-compose up -d
```

## Script de gerenciamento
- Ajuda de gerenciamento

  `bm help`

- Ver informações padrão de login

  `bm default`

- Mostrar registro DNS do domínio

  `bm show-record`

- Atualizar BillionMail

  `bm update`

## Demonstração ao Vivo
Demo do BillionMail: [https://demo.billionmail.com/billionmail](https://demo.billionmail.com/billionmail)

Nome de usuário: `billionmail` 

Senha: `billionmail` 


## WebMail

O BillionMail integrou o **RoundCube**, você pode acessar o WebMail via `/roundcube/`.

## Por que BillionMail?

A maioria das plataformas de marketing por email são **caras**, **código fechado** ou **carecem de recursos essenciais**. O BillionMail pretende ser diferente:

✅ **Totalmente Open-Source** – Sem custos ocultos, sem dependência de fornecedor.  
📊 **Análises Avançadas** – Rastreie entrega de email, taxas de abertura, taxas de clique e muito mais.  
📧 **Envio Ilimitado** – Sem restrições no número de emails que você pode enviar.  
🎨 **Modelos Personalizáveis** – Modelos de marketing profissionais personalizados para reutilização.
🔒 **Privacidade em Primeiro Lugar** – Seus dados ficam com você, sem rastreamento de terceiros.  
🚀 **Auto-hospedado** – Execute em seu próprio servidor para controle completo.  

## Como Você Pode Ajudar 🌟

O BillionMail é um **projeto orientado pela comunidade**, e precisamos do seu apoio para começar! Veja como você pode ajudar:

1. **Dar Estrela a Este Repositório**: Mostre seu interesse dando estrela a este repositório.  
2. **Espalhar a Palavra**: Compartilhe o BillionMail com sua rede—desenvolvedores, profissionais de marketing e entusiastas de código aberto.  
3. **Compartilhar Feedback**: Nos informe quais recursos você gostaria de ver no BillionMail abrindo uma issue ou participando da discussão.  
4. **Contribuir**: Uma vez que o desenvolvimento comece, daremos as boas-vindas às contribuições da comunidade. Fique atento às atualizações!

---

📧 **BillionMail – O Futuro do Marketing por Email Open-Source.**

## Issues

Se você encontrar algum problema ou tiver solicitações de recursos, por favor [abra uma issue](https://github.com/aaPanel/BillionMail/issues). Certifique-se de incluir:

- Uma descrição clara do problema ou solicitação.
- Passos para reproduzir o problema (se aplicável).
- Capturas de tela ou logs de erro (se aplicável).

## Instalar Agora:
✅Leva **apenas 8 minutos** da instalação ao **envio bem-sucedido de email**
```shell
cd /opt && git clone https://github.com/aaPanel/BillionMail && cd BillionMail && bash install.sh
```


**Instalar com Docker:** (Por favor, instale o Docker e docker-compose-plugin manualmente, e modifique o arquivo .env)
```shell
cd /opt && git clone https://github.com/aaPanel/BillionMail && cd BillionMail && cp env_init .env && docker compose up -d || docker-compose up -d
```

## Histórico de Estrelas

[![Star History Chart](https://api.star-history.com/svg?repos=aapanel/billionmail&type=Date)](https://www.star-history.com/#aapanel/billionmail&Date)

## Licença

O BillionMail está licenciado sob a **Licença AGPLv3**. Isso significa que você pode:

✅ Usar o software gratuitamente.  
✅ Modificar e distribuir o código.  
✅ Usá-lo privadamente sem restrições.

Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

---

<!-- BillionMail official link -->
[docs-link]: https://www.billionmail.com/

<!-- BillionMail Other link-->
[license-link]: https://www.gnu.org/licenses/agpl-3.0.html
[github-release-link]: https://github.com/aaPanel/BillionMail/releases/latest
[github-stars-link]: https://github.com/aaPanel/BillionMail
[github-issues-link]: https://github.com/aaPanel/BillionMail/issues

<!-- Shield link-->
[docs-shield]: https://img.shields.io/badge/documentation-148F76
[github-release-shield]: https://img.shields.io/github/v/release/aaPanel/BillionMail
[github-stars-shield]: https://img.shields.io/github/stars/aaPanel/BillionMail?color=%231890FF&style=flat-square   
[license-shield]: https://img.shields.io/github/license/aaPanel/BillionMail