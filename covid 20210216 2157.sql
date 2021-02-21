-- MySQL Administrator dump 1.4
--
-- ------------------------------------------------------
-- Server version	5.0.77-community-nt


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;


--
-- Create schema covid
--

CREATE DATABASE IF NOT EXISTS covid;
USE covid;

--
-- Definition of table `login`
--

DROP TABLE IF EXISTS `login`;
CREATE TABLE `login` (
  `row_id` int(11) NOT NULL auto_increment,
  `userid` varchar(80) default NULL,
  `password` varchar(150) default NULL,
  PRIMARY KEY  USING BTREE (`row_id`)
) ENGINE=MyISAM AUTO_INCREMENT=14 DEFAULT CHARSET=utf8;

--
-- Dumping data for table `login`
--

/*!40000 ALTER TABLE `login` DISABLE KEYS */;
INSERT INTO `login` (`row_id`,`userid`,`password`) VALUES 
 (4,'LUIS KITNIVERR','$2a$10$QtIhQ2gSzuPbuYJqbI5n5.eoFK9gq5bXmZyiJHhNI1IBbzOe4DeW.'),
 (3,'ADMON','$2a$10$gRqlsp6UjJCUgQRGrMSBW.D38ocQLy2uvkF4lbb23E9fkwiStvhK2'),
 (5,'KEINNER JOHAN','$2a$10$AOC1fj2hPJRaCtrIcvAFU.E62ZHZaZONhCe8Zey7FQTEAaxL9bpX.'),
 (6,'LUZ DARY LOPEZ','$2a$10$KQta29bQnM85joZiLg4nh.tXkPj3v3VvoYaWcvIugtwlz4PL9K5qy'),
 (7,'KITNI','$2a$10$w09Lc18TlgfvTV5RnYDpbeH4zyCoaYKQaYzsCOa.kMFR90pO2PZ22'),
 (8,'','$2a$10$y1ufg.Uw2HAnHE3kMRJ8H.zUpRtx6HRRbvpxZshpRvFvQ61Q1HA/.'),
 (9,'JOSE','$2a$10$kkxkuZwgOSvv0f5f866cEOvvNDEIGxv7zgkR66LDLAnNeoBbQD.Xe'),
 (10,'KINITO','$2a$10$4IVCxN1ieO9tlexu6P5d6O96fazExFQOAMrzjuz91EX2l3V86sHWm'),
 (11,'GOL','$2a$10$bHTfMIaoopI/RAmJFIWObews9P0iBjQWGFgcwQ7clhdKv/tDQ47eG'),
 (12,'NNNNN','$2a$10$28Xlo5g9esxuqUYA7KJ9aev3mq738nNi/mISwhO5nI1nktD1xdnj.'),
 (13,'LOCO DE LA CAS','$2a$10$anOkh3EGsV0eKuic6tNSe.h8B.oAGFA7QAprDTZRbL6xNiOULCfC2');
/*!40000 ALTER TABLE `login` ENABLE KEYS */;




/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;