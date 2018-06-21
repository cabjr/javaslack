-------------------------------------------------
-                                               -
-	Chat Criptografado Slack	     	-
-						-
-------------------------------------------------
<!-- markdown-toc start - Don't edit this section. Run M-x markdown-toc-generate-toc again -->
**Sumário**
	- [Objetivos](#objetivos)
    - [Erros para Corrigir](#erros)
	- [Para Fazer](#fazer)

<!-- markdown-toc end -->
### Objetivos
* Criptografar as mensagens
* Exportar as mensagens para MIT

### Erros
* No listMessages, algumas vezes vem com o id do Usuario
* No listMessages, as mensagens que contem <@UACQRHHFD> não estão sendo trocadas para o nome do usuario
* No listMessages, remover o scroll horizontal. Quebrar linha - OK

### Fazer
* Separa por data as mensagens 
* No metodo SlackImpl.downloadFile implementar uma forma de o usuario trocar de nome o arquivo
