# Contribuer à GoProxify

Merci de contribuer. Ce dépôt GitHub est la **vue publique** du projet
(branche `public/main`). La source de vérité interne est synchronisée via un
pipeline clean-room — les PR GitHub doivent cibler **ce** dépôt public.

## Avant de commencer

1. Lire [DISCLAIMER.md](DISCLAIMER.md) (préversion, sans garantie).
2. Lire [SECURITY.md](SECURITY.md) pour les failles (pas d’issue publique).
3. Respecter le [Code of Conduct](CODE_OF_CONDUCT.md).
4. Ouvrir une issue pour discuter des changements non triviaux.

## Développement

Prérequis : Go (voir `go.mod`), Docker, `golangci-lint`.

```bash
git clone https://github.com/Vincamok/goproxify.git
cd goproxify
go test ./...
golangci-lint run
```

Images locales (hôte de build) :

```bash
make test-prebuild   # si disponible
make docker-all REGISTRY=ghcr.io/vincamok/goproxify
```

## Pull requests

- Une PR = un sujet clair ; message de commit en français ou anglais, style
  impératif (« add X », « fix Y »).
- Inclure tests pour tout comportement nouveau ou corrigé.
- Mettre à jour `suivi/changelog.md` (`[Unreleased]`) si l’utilisateur voit
  le changement.
- Cocher le template PR.

### Developer Certificate of Origin (DCO)

Chaque commit doit être signé :

```bash
git commit -s -m "message"
```

Cela ajoute `Signed-off-by: Name <email>`, attestant le
[DCO 1.1](https://developercertificate.org/).

## Ce qu’il ne faut pas faire

- Ne pas ouvrir de PR vers un dépôt Harness / registry privé.
- Ne pas committer de secrets, IPs privées, configs `internal/*/config.json`.
- Ne pas référencer d’hôtes internes dans la doc publique.

## Support

- Questions : [GitHub Discussions](https://github.com/Vincamok/goproxify/discussions)
- Bugs / features : issues avec les templates fournis
- Sécurité : Advisories uniquement
