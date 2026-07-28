# Release notes

## v0.1.0 release-integrity note

The immutable `v0.1.0` tag points to commit
`d0587e17bc4fc387c11e8df317cc85e6aa8c2f4a`. The files attached to the
GitHub `v0.1.0` release are byte-identical to the same paths at the later
master commit `ed854a50801a050ebf9932ac99af522f76caa4a6`, which was the
master tip when the assets were uploaded. They are not byte-identical to the
tagged tree.

At that tagged revision, `aixray-review-pack.sh` is absent and
`aixray-aix.sh` has SHA-256
`e098e0b0f617649ba29fbf1626fefb55bcd2b467c09060bdcb4458b1340e5b16`.
The attached `v0.1.0` assets have these SHA-256 values:

```text
aixray-aix.sh
6829bd1aa6d24648c8c142287afc0aef730cc081716250d7eb79297c61ebaf52

aixray-review-pack.sh
8291000be2093176fc43164905958964d1e7bf9e197974abb54a25eabaab1ff4
```

### Text for the GitHub v0.1.0 release body

```text
Release-integrity note: the files attached to this release correspond to
commit ed854a50801a050ebf9932ac99af522f76caa4a6, not to the immutable
v0.1.0 tag at d0587e17bc4fc387c11e8df317cc85e6aa8c2f4a. The attached
aixray-aix.sh SHA-256 is
6829bd1aa6d24648c8c142287afc0aef730cc081716250d7eb79297c61ebaf52;
the attached aixray-review-pack.sh SHA-256 is
8291000be2093176fc43164905958964d1e7bf9e197974abb54a25eabaab1ff4.
The review helper is absent from the tagged tree, whose aixray-aix.sh
SHA-256 is
e098e0b0f617649ba29fbf1626fefb55bcd2b467c09060bdcb4458b1340e5b16.
```
