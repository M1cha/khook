int printk(const char *fmt, ...);

int module_init(void) {
	printk("[kmod] Hello World :)\n");

	return 0;
}
