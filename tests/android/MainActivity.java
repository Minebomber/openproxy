package org.openproxy.fixture;

import android.app.Activity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URL;
import org.json.JSONObject;

/** Disposable acceptance app. The local fixture supplies all destinations and bytes. */
public final class MainActivity extends Activity {
    private JSONObject request(String address, boolean post) throws Exception {
        JSONObject result = new JSONObject();
        HttpURLConnection connection = null;
        try {
            result.put("proxy", ProxySelector.getDefault().select(new URI(address)).toString());
            connection = (HttpURLConnection) new URL(address).openConnection();
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);
            if (post) {
                byte[] body = new byte[] {0, (byte) 255, 1, 2};
                connection.setRequestMethod("POST");
                connection.setDoOutput(true);
                connection.setFixedLengthStreamingMode(body.length);
                connection.getOutputStream().write(body);
                connection.getOutputStream().close();
            }
            result.put("status", connection.getResponseCode());
            try (InputStream input = connection.getInputStream();
                 ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[4096];
                int count;
                while ((count = input.read(buffer)) != -1) {
                    if (output.size() + count > 1048576) throw new Exception("fixture response too large");
                    output.write(buffer, 0, count);
                }
                result.put("body", Base64.encodeToString(output.toByteArray(), Base64.NO_WRAP));
            }
        } catch (Exception error) {
            result.put("error", error.getClass().getSimpleName());
            String message = String.valueOf(error.getMessage());
            result.put("message", message.substring(0, Math.min(message.length(), 512)));
        } finally {
            if (connection != null) connection.disconnect();
        }
        return result;
    }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        final TextView text = new TextView(this);
        text.setText("Running OpenProxy local acceptance...");
        setContentView(text);
        new Thread(() -> {
            try {
                JSONObject result = new JSONObject();
                result.put("run", getIntent().getStringExtra("run"));
                // Startup can finish before network access and the proxy-change broadcast.
                long deadline = System.nanoTime() + 20000000000L;
                JSONObject setup;
                do {
                    setup = request("http://openproxy.local/ca.pem", false);
                    if (setup.optInt("status") == 200) break;
                    Thread.sleep(200);
                } while (System.nanoTime() < deadline);
                result.put("ca", setup);
                result.put("http", request(getIntent().getStringExtra("http_url"), true));
                result.put("https", request(getIntent().getStringExtra("https_url"), false));
                Log.i("OpenProxyFixture", result.toString());
                runOnUiThread(() -> text.setText(result.toString()));
            } catch (Exception error) {
                Log.e("OpenProxyFixture", "fixture failed", error);
            }
        }).start();
    }
}
