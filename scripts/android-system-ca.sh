#!/bin/sh
# Add the OpenProxy CA to the system and user CA stores of an Android emulator.
# Use a Google APIs or AOSP image. Google Play images do not allow adb root.
# Android 14+ reads system CAs from the Conscrypt APEX in each app mount namespace.
# The system CA stays until the next cold boot. Run the script again after a cold boot.
# Chrome ignores added system CAs. It uses the user CA, which stays after reboot.
# Method: https://httptoolkit.com/blog/android-14-install-system-ca-certificate/
set -eu
ca=${1:-data/ca.pem}
name=$(openssl x509 -inform PEM -subject_hash_old -noout -in "$ca").0
adb root >/dev/null
adb wait-for-device
adb push "$ca" "/data/local/tmp/$name" >/dev/null
# Android keeps user CAs in DER format.
openssl x509 -in "$ca" -outform der | adb exec-in "cat > /data/local/tmp/$name.der"
adb shell "NAME=$name sh -s" <<'EOF'
set -e
user=/data/misc/user/0/cacerts-added
mkdir -p "$user"
mv "/data/local/tmp/$NAME.der" "$user/$NAME"
chown -R system:system "$user"
chmod 755 "$user"
chmod 644 "$user/$NAME"
restorecon -R "$user" >/dev/null 2>&1
umount /system/etc/security/cacerts 2>/dev/null || true
copy=/data/local/tmp/openproxy-cacerts
rm -rf "$copy" && mkdir -m 700 "$copy"
cp /apex/com.android.conscrypt/cacerts/* "$copy/"
mount -t tmpfs tmpfs /system/etc/security/cacerts
mv "$copy"/* /system/etc/security/cacerts/
mv "/data/local/tmp/$NAME" /system/etc/security/cacerts/
rmdir "$copy"
chown root:root /system/etc/security/cacerts/*
chmod 644 /system/etc/security/cacerts/*
chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*
# Apps copy the zygote mounts at startup. Running apps need their own mount.
zygotes=$(pidof zygote zygote64 || true)
for pid in $zygotes $(for z in $zygotes; do ps -o PID= -P "$z"; done); do
  nsenter --mount="/proc/$pid/ns/mnt" -- mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts &
done
wait
echo "System and user CA added: $NAME"
EOF
