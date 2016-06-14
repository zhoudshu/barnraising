/*
SQLyog v10.2 
MySQL - 5.1.56-LTOPS-log : Database - mydns
*********************************************************************
*/

/*!40101 SET NAMES utf8 */;

/*!40101 SET SQL_MODE=''*/;

/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
CREATE DATABASE /*!32312 IF NOT EXISTS*/`mydns` /*!40100 DEFAULT CHARACTER SET utf8 */;

USE `mydns`;

/*Table structure for table `ptr` */

DROP TABLE IF EXISTS `ptr`;

CREATE TABLE `ptr` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `ip` int(10) unsigned NOT NULL,
  `name` char(255) NOT NULL,
  `ttl` int(10) unsigned NOT NULL DEFAULT '86400',
  PRIMARY KEY (`id`),
  UNIQUE KEY `ip` (`ip`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

/*Data for the table `ptr` */

/*Table structure for table `rr` */

DROP TABLE IF EXISTS `rr`;

CREATE TABLE `rr` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `zone` int(10) unsigned NOT NULL,
  `name` char(63) NOT NULL,
  `type` enum('A','AAAA','CNAME','MX','NS','TXT') DEFAULT NULL,
  `data` char(255) NOT NULL,
  `aux` int(10) unsigned NOT NULL,
  `ttl` int(10) unsigned NOT NULL DEFAULT '86400',
  PRIMARY KEY (`id`),
  UNIQUE KEY `rr` (`zone`,`name`,`type`,`data`)
) ENGINE=MyISAM AUTO_INCREMENT=113 DEFAULT CHARSET=utf8;

/*Data for the table `rr` */

insert  into `rr`(`id`,`zone`,`name`,`type`,`data`,`aux`,`ttl`) values (1,2,'impd','A','10.10.100.1',0,300),(112,2,'www','A','10.10.100.1',0,300);

/*Table structure for table `soa` */

DROP TABLE IF EXISTS `soa`;

CREATE TABLE `soa` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `origin` char(78) NOT NULL,
  `ns` char(255) NOT NULL,
  `mbox` char(255) NOT NULL,
  `serial` int(10) unsigned NOT NULL DEFAULT '1',
  `refresh` int(10) unsigned NOT NULL DEFAULT '28800',
  `retry` int(10) unsigned NOT NULL DEFAULT '7200',
  `expire` int(10) unsigned NOT NULL DEFAULT '604800',
  `minimum` int(10) unsigned NOT NULL DEFAULT '86400',
  `ttl` int(10) unsigned NOT NULL DEFAULT '86400',
  PRIMARY KEY (`id`),
  UNIQUE KEY `origin` (`origin`)
) ENGINE=MyISAM AUTO_INCREMENT=4 DEFAULT CHARSET=utf8;

/*Data for the table `soa` */

insert  into `soa`(`id`,`origin`,`ns`,`mbox`,`serial`,`refresh`,`retry`,`expire`,`minimum`,`ttl`) values (2,'zhouds.cn.','','',1464683133,0,0,0,0,300);

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
