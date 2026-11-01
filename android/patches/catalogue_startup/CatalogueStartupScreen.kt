package com.secureconnect.app.ui.screens.home

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.secureconnect.app.viewmodel.CatalogueStartupPolicy

/** No fake percentage: the catalogue is partial until the first compatible list arrives. */
@Composable
internal fun CatalogueStartupScreen(
    status: CatalogueStartupPolicy.State,
    onRetry: () -> Unit,
    onSettings: () -> Unit
) {
    Box(
        Modifier.fillMaxSize().background(Brush.verticalGradient(
            listOf(Color(0xFF17112E), Color(0xFF090E26), Color(0xFF040815)))),
        contentAlignment = Alignment.Center
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().widthIn(max = 420.dp)
                .padding(horizontal = 24.dp, vertical = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text("vipineshka vpn", style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold, color = Color(0xFFECE6FF))
            Spacer(Modifier.height(12.dp))
            if (status.phase == CatalogueStartupPolicy.Phase.LOADING) {
                CircularProgressIndicator(color = Color(0xFFAE85FF))
            }
            Text(
                if (status.phase == CatalogueStartupPolicy.Phase.ERROR)
                    "Не удалось загрузить список серверов" else "Загружается список серверов",
                color = Color.White, style = MaterialTheme.typography.titleLarge,
                textAlign = TextAlign.Center
            )
            Text(status.detail, color = Color(0xFFCAD1E8), textAlign = TextAlign.Center)
            Text("Найдено в каталоге: ${status.storedCount} · максимум 240. " +
                "Это число не означает, что все серверы доступны.",
                color = Color(0xFFACB6D0), textAlign = TextAlign.Center,
                style = MaterialTheme.typography.bodySmall)
            Text("Подключение VPN станет доступно после загрузки совместимых " +
                "конфигураций или обнаружения сохранённого проверенного резерва.",
                color = Color(0xFFACB6D0), textAlign = TextAlign.Center,
                style = MaterialTheme.typography.bodySmall)
            if (status.phase == CatalogueStartupPolicy.Phase.ERROR) {
                Button(onClick = onRetry, shape = RoundedCornerShape(12.dp)) {
                    Text("Повторить загрузку")
                }
            }
            OutlinedButton(onClick = onSettings) { Text("Настройки") }
        }
    }
}