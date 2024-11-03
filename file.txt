package com.shtrokfm.quadrober.shared.component;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class SignatureFilter implements Filter {
  @Value("${bot.auth.disabled}")
  private String botAuthDisabled;

  @Value("${bot.token}")
  private String botToken;

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
    throws IOException, ServletException {

    HttpServletRequest httpRequest = (HttpServletRequest) request;
    HttpServletResponse httpResponse = (HttpServletResponse) response;

    String path = httpRequest.getRequestURI();

    // Пропускаем запросы к /public
    if (path.startsWith("/public") || this.botAuthDisabled.equals("true")) {
      chain.doFilter(request, response);
      return;
    }

    // Извлекаем данные из заголовка Authorization
    String authorizationHeader = httpRequest.getHeader("Authorization");
    if (authorizationHeader == null || !authorizationHeader.startsWith("twa-init-data ")) {
      httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing or invalid Authorization header");
      return;
    }

    // Извлекаем данные
    String data = authorizationHeader.replace("twa-init-data ", "");

    if (!checkSignature(data, botToken)) {
      httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid signature");
      return;
    }

    // Если подпись валидна, продолжаем выполнение цепочки фильтров
    chain.doFilter(request, response);
  }

  private boolean checkSignature(String data, String botToken) {
    Map<String, String> vals = new HashMap<>();
    for (String pair : data.split("&")) {
      String[] keyValue = pair.split("=", 2);
      String key = keyValue[0];
      String value = URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);
      vals.put(key, value);
    }

    // Формируем строку для проверки
    String dataCheckString = vals.entrySet().stream()
            .filter(entry -> !entry.getKey().equals("hash"))
            .sorted(Map.Entry.comparingByKey())
            .map(entry -> entry.getKey() + "=" + entry.getValue())
            .collect(Collectors.joining("\n"));

    // Вычисляем секретный ключ
    byte[] secretKey = hmacSha256("WebAppData", botToken);
    // Вычисляем хэш
    String computedHash = hmacSha256Hex(secretKey, dataCheckString);

    // Сравнение хэшей
    return computedHash.equals(vals.get("hash"));
  }

  private static byte[] hmacSha256(String key, String data) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
      mac.init(secretKeySpec);
      return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
      throw new RuntimeException("Failed to calculate HMAC SHA-256", e);
    }
  }

  private static String hmacSha256Hex(byte[] key, String data) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA256");
      mac.init(secretKeySpec);
      byte[] hashBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
      StringBuilder hash = new StringBuilder();
      for (byte b : hashBytes) {
        hash.append(String.format("%02x", b));
      }
      return hash.toString();
    } catch (Exception e) {
      throw new RuntimeException("Failed to calculate HMAC SHA-256", e);
    }
  }
}
