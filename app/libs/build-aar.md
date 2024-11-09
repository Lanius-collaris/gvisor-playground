## Example
```
cd aegis
gomobile bind -trimpath -ldflags '-w -s' -androidapi 21 \
-target=android/amd64,android/arm64 -tags='android' -o ../aegis.aar ./android_interface
```
