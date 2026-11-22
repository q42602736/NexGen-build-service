package main

// 专用构建通过 Go overlay 注入完整配置；仓库不保存真实配置值。
var embeddedEnvironment = map[string]string{}
